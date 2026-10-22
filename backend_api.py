"""
API Backend Segura em FastAPI para o CipherSong (`senior-architect` + `security-specialist`).

Propósito de Segurança (AppSec):
- O APK Mobile nunca armazena a `MONGODB_URI` nem a senha do banco de dados.
- Autenticação e Registro com E-mail e Senha protegidos por PBKDF2-HMAC-SHA256 e Tokens JWT.
- Suporte a repertório isolado por usuário (`usuario_id`) e modo convidado retrocompatível.
- Esta API roda no servidor Render (https://ciphersong.onrender.com) e localmente nos testes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from typing import Any, Optional

logger = logging.getLogger(__name__)

import secrets
import urllib.parse

import httpx
from bson import ObjectId
from fastapi import FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ciphersong.database.mongo_connection import (
    EquipesRepository,
    MusicasAEnsaiarRepository,
    MusicasEnsaioRepository,
    PingsRepository,
    RepertorioSemanaRepository,
    UsuariosRepository,
)
from ciphersong.security.auth import (
    create_access_token,
    decode_access_token,
    hash_password,
    validate_email,
    validate_password,
    verify_password,
)
from ciphersong.security.otp import (
    OTPRateLimitError,
    OTPVerificationError,
    default_otp_manager,
)
from ciphersong.services.email_service import default_email_service

app = FastAPI(
    title="CipherSong Cloud API",
    description="Backend seguro com autenticação de usuários, isolamento multi-equipes e sincronização de músicas com o MongoDB Atlas.",
    version="1.4.0",
)

# Suporte amplo a CORS para clientes web e requisições assíncronas do Flutter Web
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class UserRegisterPayload(BaseModel):
    email: str = Field(..., description="E-mail do usuário")
    senha: str = Field(..., min_length=6, description="Senha de acesso (mínimo 6 caracteres)")
    nome: Optional[str] = Field(default=None, description="Nome ou apelido do músico")


class UserLoginPayload(BaseModel):
    email: str = Field(..., description="E-mail cadastrado")
    senha: str = Field(..., description="Senha de acesso")


class UserGoogleAuthPayload(BaseModel):
    email: str = Field(..., description="E-mail da conta Google")
    nome: Optional[str] = Field(default=None, description="Nome de usuário escolhido")


class OTPRequestPayload(BaseModel):
    email: str = Field(..., description="E-mail do usuário para envio do código")
    nome: Optional[str] = Field(default=None, description="Nome de usuário (opcional para novo cadastro)")


class OTPVerifyPayload(BaseModel):
    email: str = Field(..., description="E-mail do usuário")
    codigo: str = Field(..., min_length=6, max_length=6, description="Código de 6 dígitos recebido por e-mail")
    nome: Optional[str] = Field(default=None, description="Nome de exibição desejado")


class UserChangeNamePayload(BaseModel):
    novo_nome: str = Field(..., min_length=2, max_length=50, description="Novo nome de usuário")


class EquipeCreatePayload(BaseModel):
    nome: str = Field(..., min_length=2, max_length=60, description="Nome da equipe")


class EquipeEntrarPayload(BaseModel):
    codigo: str = Field(..., min_length=4, max_length=30, description="Código de convite da equipe")


class MusicaCreatePayload(BaseModel):
    titulo: str = Field(..., min_length=1, description="Nome da música ensaiada")
    cantor_principal: str = Field(..., min_length=1, description="Nome do solista / cantor principal")
    tons: list[str] = Field(..., min_length=1, description="Lista de tons da música (ex: ['G', 'Em'])")
    versao: Optional[str] = Field(default="Original", description="Versão ou arranjo da cifra tocada")
    equipe_id: Optional[str] = Field(default=None, description="ID da equipe dona da música")


class RepertorioSemanaCreatePayload(BaseModel):
    musica_id: str = Field(..., description="ID da música no acervo")
    titulo: str = Field(..., min_length=1, description="Nome da música")
    cantor_principal: str = Field(..., min_length=1, description="Solista do dia")
    tom_selecionado: str = Field(..., min_length=1, description="Tom escolhido para o ensaio/culto")
    data_ensaio: str = Field(..., min_length=10, description="Data no formato YYYY-MM-DD")
    dia_semana: str = Field(..., min_length=1, description="Ex: Sábado")
    versao: Optional[str] = Field(default="Original", description="Versão da cifra")
    adicionado_por: Optional[str] = Field(default=None, description="Nome de quem agendou")
    equipe_id: Optional[str] = Field(default=None, description="ID da equipe dona do agendamento")


class MusicaAEnsaiarCreatePayload(BaseModel):
    titulo: str = Field(..., min_length=1, description="Nome da música a ensaiar")
    cantor_versao: str = Field(..., min_length=1, description="Cantor e/ou versão de referência")
    youtube_url: Optional[str] = Field(default="", description="Link direto para o vídeo no YouTube")
    adicionado_por: Optional[str] = Field(default=None, description="Nome de quem sugeriu")
    equipe_id: Optional[str] = Field(default=None, description="ID da equipe dona da sugestão")


class PingCreatePayload(BaseModel):
    destinatario_id: str = Field(..., description="ID do usuário a ser chamado")
    destinatario_nome: Optional[str] = Field(default="", description="Nome do usuário chamado")
    equipe_id: Optional[str] = Field(default=None, description="ID da equipe onde a chamada foi feita")


def get_repo() -> MusicasEnsaioRepository:
    return MusicasEnsaioRepository()


def get_users_repo() -> UsuariosRepository:
    return UsuariosRepository()


def get_semana_repo() -> RepertorioSemanaRepository:
    return RepertorioSemanaRepository()


def get_a_ensaiar_repo() -> MusicasAEnsaiarRepository:
    return MusicasAEnsaiarRepository()


def get_pings_repo() -> PingsRepository:
    return PingsRepository()


def get_equipes_repo() -> EquipesRepository:
    return EquipesRepository()


def verify_user_in_team(equipe_id: Optional[str], usuario_id: Optional[str]) -> Optional[str]:
    """Valida se o usuário pertence à equipe informada e retorna o ID da equipe resolvida."""
    try:
        equipes_repo = get_equipes_repo()
    except Exception:
        return str(equipe_id).strip() if equipe_id else None

    if not equipe_id or not str(equipe_id).strip():
        return None

    resolved_id = str(equipe_id).strip()
    if usuario_id:
        try:
            if not equipes_repo.usuario_pertence_a_equipe(resolved_id, usuario_id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Você não tem permissão para acessar os dados desta equipe.",
                )
        except HTTPException:
            raise
        except Exception:
            pass
    return resolved_id


def _call_repo(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Invoca o método do repositório adaptando dinamicamente os argumentos suportados pela assinatura."""
    try:
        import inspect
        sig = inspect.signature(fn)
        has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        if not has_var_kw:
            accepted_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
            return fn(*args, **accepted_kwargs)
    except (ValueError, TypeError):
        pass
    return fn(*args, **kwargs)




def extract_user_id(authorization: Optional[str]) -> Optional[str]:
    """Extrai com segurança o ID do usuário autenticado a partir do cabeçalho Bearer Token."""
    if not authorization:
        return None
    claims = decode_access_token(authorization)
    if claims and "sub" in claims:
        return str(claims["sub"])
    return None


# =============================================================================
# GERENCIAMENTO DE WEBSOCKETS EM TEMPO REAL (REAL-TIME SYNC)
# =============================================================================

class TeamConnectionManager:
    """Gerencia conexões WebSocket ativas divididas por equipe para sincronização em tempo real."""

    def __init__(self) -> None:
        self.active_connections: dict[str, list[tuple[WebSocket, str]]] = {}
        self._in_process_listeners: list[Any] = []
        self._lock = asyncio.Lock()

    def add_listener(self, listener: Any) -> None:
        if listener not in self._in_process_listeners:
            self._in_process_listeners.append(listener)

    def remove_listener(self, listener: Any) -> None:
        if listener in self._in_process_listeners:
            self._in_process_listeners.remove(listener)

    async def connect(self, websocket: WebSocket, equipe_id: str, usuario_id: str) -> None:
        await websocket.accept()
        async with self._lock:
            if equipe_id not in self.active_connections:
                self.active_connections[equipe_id] = []
            self.active_connections[equipe_id].append((websocket, usuario_id))

    async def disconnect(self, websocket: WebSocket, equipe_id: str) -> None:
        async with self._lock:
            if equipe_id in self.active_connections:
                self.active_connections[equipe_id] = [
                    (ws, uid) for (ws, uid) in self.active_connections[equipe_id] if ws != websocket
                ]
                if not self.active_connections[equipe_id]:
                    del self.active_connections[equipe_id]

    async def broadcast_to_team(
        self,
        equipe_id: str,
        event_type: str,
        data: dict[str, Any],
        exclude_user_id: Optional[str] = None,
    ) -> None:
        if not equipe_id:
            return
        async with self._lock:
            targets = list(self.active_connections.get(equipe_id, []))

        payload = {
            "event": event_type,
            "equipe_id": equipe_id,
            "data": data,
        }
        dead_connections: list[WebSocket] = []

        for ws, uid in targets:
            if exclude_user_id and uid == exclude_user_id:
                continue
            try:
                await ws.send_json(payload)
            except Exception:
                dead_connections.append(ws)

        if dead_connections:
            async with self._lock:
                if equipe_id in self.active_connections:
                    self.active_connections[equipe_id] = [
                        (ws, uid) for (ws, uid) in self.active_connections[equipe_id] if ws not in dead_connections
                    ]


team_ws_manager = TeamConnectionManager()


def dispatch_team_event(
    equipe_id: Optional[str],
    event_type: str,
    data: dict[str, Any],
    exclude_user_id: Optional[str] = None,
) -> None:
    """Dispara um evento em tempo real para os membros da equipe conectada via WebSocket e sessões web in-process."""
    if not equipe_id:
        return

    # Notifica ouvintes in-process (sessões web Flet rodando na mesma instância)
    for listener in list(team_ws_manager._in_process_listeners):
        try:
            listener(equipe_id, event_type, data, exclude_user_id)
        except Exception as _sub_err:
            logger.debug("Falha ao notificar ouvinte in-process: %s", _sub_err)

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(team_ws_manager.broadcast_to_team(equipe_id, event_type, data, exclude_user_id))
    except RuntimeError:
        threading.Thread(
            target=lambda: asyncio.run(team_ws_manager.broadcast_to_team(equipe_id, event_type, data, exclude_user_id)),
            daemon=True,
        ).start()


@app.websocket("/api/ws/events")
async def websocket_events_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None, description="Token JWT de autenticação via Query Param"),
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe ativa"),
):
    """
    Canal de eventos em tempo real via WebSocket.
    Permite autenticação do token JWT via Query Param (?token=...) para suporte em navegadores/Safari
    ou via cabeçalho Authorization se enviado por clientes nativos.
    """
    raw_token = token
    if not raw_token:
        auth_header = websocket.headers.get("authorization")
        if auth_header:
            raw_token = auth_header.replace("Bearer ", "").strip()

    usuario_id = None
    if raw_token:
        try:
            claims = decode_access_token(raw_token)
            if claims and "sub" in claims:
                usuario_id = str(claims["sub"])
        except Exception:
            usuario_id = None

    if not usuario_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    resolved_equipe_id = verify_user_in_team(equipe_id, usuario_id)
    if not resolved_equipe_id:
        resolved_equipe_id = f"user_{usuario_id}"

    await team_ws_manager.connect(websocket, resolved_equipe_id, usuario_id)
    try:
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await team_ws_manager.disconnect(websocket, resolved_equipe_id)
    except Exception:
        await team_ws_manager.disconnect(websocket, resolved_equipe_id)


@app.get("/health")
@app.get("/api/health")
def health_check() -> dict[str, Any]:
    return {"status": "ok", "service": "ciphersong-api"}


# =============================================================================
# ROTAS DE AUTENTICAÇÃO (CADASTRO E LOGIN POR E-MAIL E SENHA)
# =============================================================================

@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def registrar_usuario(payload: UserRegisterPayload) -> dict[str, Any]:
    """Cria uma nova conta de usuário com senha criptografada por PBKDF2-HMAC-SHA256."""
    clean_email = payload.email.strip().lower()
    if not validate_email(clean_email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Endereço de e-mail inválido. Verifique o formato digitado.",
        )

    pwd_valid, pwd_msg = validate_password(payload.senha)
    if not pwd_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pwd_msg)

    hashed = hash_password(payload.senha)
    users_repo = get_users_repo()

    try:
        user_doc = users_repo.criar_usuario(
            email=clean_email,
            senha_hash=hashed,
            nome=payload.nome,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Erro no banco: {exc}") from exc

    token = create_access_token(
        user_id=user_doc["_id"],
        email=user_doc["email"],
        name=user_doc.get("nome"),
    )

    return {
        "status": "success",
        "message": "Conta criada com sucesso!",
        "token": token,
        "user": {
            "id": user_doc["_id"],
            "email": user_doc["email"],
            "nome": user_doc.get("nome", ""),
        },
    }


@app.post("/api/auth/login")
def login_usuario(payload: UserLoginPayload) -> dict[str, Any]:
    """Valida o e-mail e a senha informados e emite um token de acesso JWT."""
    clean_email = payload.email.strip().lower()
    users_repo = get_users_repo()

    try:
        user_doc = users_repo.buscar_por_email(clean_email)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Erro no banco: {exc}") from exc

    if not user_doc or not verify_password(payload.senha, user_doc.get("senha_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou senha incorretos. Verifique suas credenciais.",
        )

    token = create_access_token(
        user_id=user_doc["_id"],
        email=user_doc["email"],
        name=user_doc.get("nome"),
    )

    return {
        "status": "success",
        "message": "Login realizado com sucesso!",
        "token": token,
        "user": {
            "id": user_doc["_id"],
            "email": user_doc["email"],
            "nome": user_doc.get("nome", ""),
        },
    }


@app.post("/api/auth/google")
def login_google(payload: UserGoogleAuthPayload) -> dict[str, Any]:
    """Autentica ou registra o usuário com conta Google criptografando o token e salvando o nome de usuário."""
    clean_email = payload.email.strip().lower()
    if not validate_email(clean_email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Endereço de e-mail Google inválido.",
        )

    clean_name = (payload.nome or "").strip() or clean_email.split("@")[0]
    google_token_hash = hash_password(f"google-oauth2::{clean_email}")
    users_repo = get_users_repo()

    try:
        user_doc = users_repo.autenticar_ou_criar_google(
            email=clean_email,
            nome=clean_name,
            google_token_hash=google_token_hash,
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Erro no banco: {exc}") from exc

    token = create_access_token(
        user_id=user_doc["_id"],
        email=user_doc["email"],
        name=user_doc.get("nome", clean_name),
    )

    return {
        "status": "success",
        "message": "Autenticado com Conta Google!",
        "token": token,
        "user": {
            "id": user_doc["_id"],
            "email": user_doc["email"],
            "nome": user_doc.get("nome", clean_name),
            "provedor": "google",
        },
    }


DEFAULT_GOOGLE_CLIENT_ID = "565867015725-o8orc4t64gie24qqvgqo5df9faramcvi.apps.googleusercontent.com"
GOOGLE_CLIENT_ID = (os.getenv("GOOGLE_CLIENT_ID") or DEFAULT_GOOGLE_CLIENT_ID).strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URL = os.getenv("GOOGLE_REDIRECT_URL", "").strip()


def _resolve_google_redirect_uri(request: Request) -> str:
    """Resolve a URL de callback OAuth do Google priorizando GOOGLE_REDIRECT_URL."""
    configured = (os.getenv("GOOGLE_REDIRECT_URL") or GOOGLE_REDIRECT_URL).strip()
    if configured:
        return configured
    # Fallback dinâmico considerando reverse proxies (Cloudflare Tunnel, Fly.io, Render)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    if "," in host:
        host = host.split(",")[0].strip()
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    if proto and "," in proto:
        proto = proto.split(",")[0].strip()
    if not proto or proto not in ("http", "https"):
        proto = "https" if "localhost" not in host and "127.0.0.1" not in host else "http"
    redirect_uri = f"{proto}://{host}/api/auth/google/callback"
    logger.info("Redirect URI inferido automaticamente: %s", redirect_uri)
    return redirect_uri


@app.get("/api/auth/google/login")
def google_oauth_login(request: Request) -> RedirectResponse:
    """Redireciona o usuário para a URL de autorização oficial do Google."""
    redirect_uri = _resolve_google_redirect_uri(request)
    state = secrets.token_urlsafe(16)
    client_id = (os.getenv("GOOGLE_CLIENT_ID") or GOOGLE_CLIENT_ID).strip()

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
        "access_type": "online",
    }
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
    logger.info("Iniciando OAuth Google. Redirect URI: %s", redirect_uri)
    return RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)


@app.get("/api/auth/google/callback")
def google_oauth_callback(
    request: Request,
    code: Optional[str] = Query(default=None),
    error: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
) -> RedirectResponse:
    """Recebe o code do Google, troca pelo token, recupera perfil, emite JWT e redireciona para a raiz /."""
    if error or not code:
        err_msg = error or "Operação de login com o Google cancelada"
        logger.warning("Callback Google cancelado ou com erro: %s", err_msg)
        return RedirectResponse(url=f"/?auth_error={urllib.parse.quote(err_msg)}", status_code=status.HTTP_302_FOUND)

    client_id = (os.getenv("GOOGLE_CLIENT_ID") or GOOGLE_CLIENT_ID).strip()
    client_secret = (os.getenv("GOOGLE_CLIENT_SECRET") or GOOGLE_CLIENT_SECRET).strip()
    redirect_uri = _resolve_google_redirect_uri(request)

    # 1. Troca o código de autorização pelo token de acesso na API do Google
    try:
        with httpx.Client(timeout=12.0) as http_client:
            token_payload = {
                "code": code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            }
            if client_secret:
                token_payload["client_secret"] = client_secret

            token_resp = http_client.post(
                "https://oauth2.googleapis.com/token",
                data=token_payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            token_resp.raise_for_status()
            token_data = token_resp.json()
            access_token = token_data.get("access_token")

            # 2. Busca os dados de perfil do usuário (e-mail, nome)
            user_resp = http_client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_resp.raise_for_status()
            user_info = user_resp.json()
    except Exception as exc:
        logger.error("Falha ao validar token do Google no callback: %s", exc, exc_info=True)
        return RedirectResponse(
            url=f"/?auth_error={urllib.parse.quote('Falha na validação com os servidores do Google')}",
            status_code=status.HTTP_302_FOUND,
        )

    email = (user_info.get("email") or "").strip().lower()
    if not email:
        return RedirectResponse(
            url=f"/?auth_error={urllib.parse.quote('O Google não retornou o e-mail da conta')}",
            status_code=status.HTTP_302_FOUND,
        )

    name = (user_info.get("name") or user_info.get("given_name") or email.split("@")[0]).strip()
    google_token_hash = hash_password(f"google-oauth2::{email}")
    users_repo = get_users_repo()

    try:
        user_doc = users_repo.autenticar_ou_criar_google(
            email=email,
            nome=name,
            google_token_hash=google_token_hash,
        )
    except Exception as exc:
        logger.error("Falha ao salvar usuário autenticado no banco: %s", exc, exc_info=True)
        return RedirectResponse(
            url=f"/?auth_error={urllib.parse.quote('Erro ao salvar usuário no banco de dados')}",
            status_code=status.HTTP_302_FOUND,
        )

    # 3. Emite o token JWT do CipherSong
    token = create_access_token(
        user_id=user_doc["_id"],
        email=user_doc["email"],
        name=user_doc.get("nome", name),
    )

    # 4. Redireciona de volta para a raiz (/) com os parâmetros de autenticação e cookie de sessão
    redirect_params = urllib.parse.urlencode({
        "token": token,
        "user_id": str(user_doc["_id"]),
        "email": user_doc["email"],
        "name": user_doc.get("nome", name),
    })
    logger.info("Login Google bem-sucedido para %s. Redirecionando para /", email)
    response = RedirectResponse(url=f"/?{redirect_params}", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="ciphersong_jwt",
        value=token,
        max_age=86400 * 30,
        httponly=True,
        samesite="lax",
        secure=True,
    )
    return response



# =============================================================================
# AUTENTICAÇÃO PASSWORDLESS VIA CÓDIGO POR E-MAIL (OTP)
# =============================================================================

@app.post("/api/auth/otp/request")
def solicitar_codigo_otp(payload: OTPRequestPayload) -> dict[str, Any]:
    """
    Gera e envia um código numérico de 6 dígitos temporário (OTP) por e-mail.
    Aplica rate limiting de 60s entre reenvios e no máximo 5 solicitações por hora.
    Bloqueia contas vinculadas ao Google Auth para direcionar ao fluxo Google.
    """
    clean_email = payload.email.strip().lower()
    if not validate_email(clean_email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Endereço de e-mail inválido. Verifique o formato digitado.",
        )

    # 1. Proteção AppSec: se o e-mail já estiver cadastrado com Google Auth, bloqueia OTP
    users_repo = get_users_repo()
    try:
        existing = users_repo.buscar_por_email(clean_email)
        if existing and existing.get("provedor") == "google":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Este e-mail está cadastrado com a Conta Google. Faça login pelo botão 'Fazer Login com o Google'.",
            )
    except HTTPException:
        raise
    except Exception:
        pass

    # 2. Geração segura e rate limiting
    try:
        plain_code, cooldown, expires_min = default_otp_manager.request_otp(
            email=clean_email,
            name=payload.nome,
        )
    except OTPRateLimitError as rle:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(rle),
            headers={"Retry-After": str(rle.retry_after_seconds)},
        ) from rle

    # 3. Disparo do e-mail transacional
    try:
        default_email_service.send_otp_email(
            to_email=clean_email,
            codigo=plain_code,
            expires_in_minutes=expires_min,
        )
    except Exception as exc:
        print(f"[Email Dispatch Error]: {exc}")

    return {
        "status": "success",
        "message": f"Código de verificação enviado para {clean_email}!",
        "email": clean_email,
        "cooldown_seconds": cooldown,
        "expires_in_minutes": expires_min,
    }


@app.post("/api/auth/otp/verify")
def verificar_codigo_otp(payload: OTPVerifyPayload) -> dict[str, Any]:
    """
    Valida o código de 6 dígitos inserido pelo usuário.
    Destrói o código imediatamente após o primeiro uso válido (invalidação pós-uso).
    Autentica ou cria a conta passwordless e emite o token JWT de sessão.
    """
    clean_email = payload.email.strip().lower()
    clean_code = payload.codigo.strip()

    if not validate_email(clean_email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Endereço de e-mail inválido.",
        )

    if not clean_code or len(clean_code) != 6 or not clean_code.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O código de verificação deve conter exatamente 6 dígitos numéricos.",
        )

    # 1. Validação com destruição imediata se correto e controle de tentativas
    try:
        ok, msg, stored_name = default_otp_manager.verify_otp(
            email=clean_email,
            candidate_code=clean_code,
        )
    except OTPVerificationError as ove:
        status_code = status.HTTP_429_TOO_MANY_REQUESTS if "Limite de tentativas" in str(ove) else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=status_code, detail=str(ove)) from ove

    # 2. Login ou criação de conta passwordless
    chosen_name = (payload.nome or "").strip() or stored_name
    users_repo = get_users_repo()
    try:
        user_doc = users_repo.autenticar_ou_criar_otp(
            email=clean_email,
            nome=chosen_name,
        )
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err)) from val_err
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Erro ao acessar conta: {exc}") from exc

    token = create_access_token(
        user_id=user_doc["_id"],
        email=user_doc["email"],
        name=user_doc.get("nome", ""),
    )

    return {
        "status": "success",
        "message": "Login realizado com sucesso!",
        "token": token,
        "user": {
            "id": user_doc["_id"],
            "email": user_doc["email"],
            "nome": user_doc.get("nome", ""),
            "provedor": user_doc.get("provedor", "email_otp"),
        },
    }


@app.get("/api/auth/me")
def obter_usuario_logado(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """Retorna os dados do usuário autenticado via Bearer Token."""
    user_id = extract_user_id(authorization)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão expirada ou não autenticada. Faça login novamente.",
        )

    users_repo = get_users_repo()
    user_doc = users_repo.buscar_por_id(user_id)
    if not user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    return {
        "id": user_doc["_id"],
        "email": user_doc["email"],
        "nome": user_doc.get("nome", ""),
        "criado_em": user_doc.get("criado_em", ""),
    }


@app.put("/api/auth/nome")
def alterar_nome_usuario(
    payload: UserChangeNamePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Altera o nome de usuário do músico autenticado no MongoDB Atlas."""
    user_id = extract_user_id(authorization)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão expirada ou não autenticada. Faça login novamente.",
        )
    clean_nome = payload.novo_nome.strip()
    if not clean_nome or len(clean_nome) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O nome de usuário deve conter pelo menos 2 caracteres.",
        )

    users_repo = get_users_repo()
    try:
        updated_doc = users_repo.atualizar_nome_usuario(user_id=user_id, novo_nome=clean_nome)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Erro no banco: {exc}") from exc

    if not updated_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")

    token = create_access_token(
        user_id=updated_doc["_id"],
        email=updated_doc["email"],
        name=updated_doc.get("nome", clean_nome),
    )

    return {
        "status": "success",
        "message": f"Nome alterado com sucesso para '{clean_nome}'!",
        "token": token,
        "user": {
            "id": updated_doc["_id"],
            "email": updated_doc["email"],
            "nome": updated_doc.get("nome", clean_nome),
        },
    }


# =============================================================================
# ROTAS DO REPERTÓRIO DE MÚSICAS ENSAIADAS (COM SUPORTE A USUÁRIO)
# =============================================================================

@app.get("/api/musicas")
def listar_musicas(
    q: Optional[str] = Query(default=None, description="Termo de busca (título, versão, cantor ou tom)"),
    cantor: Optional[str] = Query(default=None, description="Filtrar por cantor específico"),
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe selecionada"),
    authorization: Optional[str] = Header(default=None),
) -> list[dict[str, Any]]:
    repo = get_repo()
    usuario_id = extract_user_id(authorization)
    resolved_equipe_id = verify_user_in_team(equipe_id, usuario_id)
    try:
        effective_user_id = None if resolved_equipe_id else usuario_id
        if (q and q.strip()) or (cantor and cantor.strip() and cantor.strip().lower() != "todos"):
            return _call_repo(
                repo.buscar_por_filtro,
                termo=q.strip() if q else "",
                cantor=cantor.strip() if cantor else None,
                usuario_id=effective_user_id,
                equipe_id=resolved_equipe_id,
            )
        return _call_repo(repo.listar_todas, usuario_id=effective_user_id, equipe_id=resolved_equipe_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao consultar MongoDB Atlas: {exc}") from exc


@app.get("/api/cantores")
def listar_cantores(
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe selecionada"),
    authorization: Optional[str] = Header(default=None),
) -> list[str]:
    repo = get_repo()
    usuario_id = extract_user_id(authorization)
    resolved_equipe_id = verify_user_in_team(equipe_id, usuario_id)
    try:
        effective_user_id = None if resolved_equipe_id else usuario_id
        return _call_repo(repo.listar_cantores_unicos, usuario_id=effective_user_id, equipe_id=resolved_equipe_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao listar cantores: {exc}") from exc


@app.post("/api/musicas", status_code=201)
def criar_musica(
    payload: MusicaCreatePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    repo = get_repo()
    usuario_id = extract_user_id(authorization)
    resolved_equipe_id = verify_user_in_team(payload.equipe_id, usuario_id)
    try:
        saved_doc = _call_repo(
            repo.salvar_musica,
            titulo=payload.titulo,
            cantor_principal=payload.cantor_principal,
            tons=payload.tons,
            versao=payload.versao or "Original",
            usuario_id=usuario_id,
            equipe_id=resolved_equipe_id,
        )
        dispatch_team_event(
            resolved_equipe_id or (f"user_{usuario_id}" if usuario_id else None),
            "songs_changed",
            {"action": "saved", "musica_id": str(saved_doc.get("_id") or saved_doc.get("id") or "")},
            exclude_user_id=usuario_id,
        )
        return saved_doc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao salvar no MongoDB Atlas: {exc}") from exc


@app.delete("/api/musicas/{song_id}")
def deletar_musica(
    song_id: str,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    repo = get_repo()
    usuario_id = extract_user_id(authorization)
    try:
        doc = repo.collection.find_one({"_id": ObjectId(song_id)})
        if not doc:
            return {"deleted": False, "id": song_id}

        doc_equipe = str(doc.get("equipe_id") or "").strip()
        doc_user = str(doc.get("usuario_id") or "").strip()

        if doc_equipe:
            # Música pertence a uma equipe: valida se o usuário pertence à equipe
            equipes_repo = get_equipes_repo()
            if usuario_id and not equipes_repo.usuario_pertence_a_equipe(doc_equipe, usuario_id):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada: você não pertence à equipe desta música.")
        elif doc_user and usuario_id and doc_user != usuario_id:
            # Música pessoal: apenas o criador pode deletar
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão negada: esta música pessoal pertence a outro usuário.")

        res = repo.collection.delete_one({"_id": ObjectId(song_id)})
        deleted = res.deleted_count > 0
        if deleted:
            dispatch_team_event(
                doc_equipe or (f"user_{doc_user}" if doc_user else None),
                "songs_changed",
                {"action": "deleted", "musica_id": song_id},
                exclude_user_id=usuario_id,
            )
        return {"deleted": deleted, "id": song_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Não foi possível remover: {exc}") from exc


# =============================================================================
# ROTAS DO REPERTÓRIO DA SEMANA (ESCALA COMPARTILHADA DA EQUIPE)
# =============================================================================

@app.get("/api/repertorio-semana")
def listar_repertorio_semana(
    data: Optional[str] = Query(default=None, description="Filtrar por data específica YYYY-MM-DD"),
    data_inicio: Optional[str] = Query(default=None, description="Data início YYYY-MM-DD"),
    data_fim: Optional[str] = Query(default=None, description="Data fim YYYY-MM-DD"),
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe"),
    authorization: Optional[str] = Header(default=None),
) -> list[dict[str, Any]]:
    """Lista as músicas agendadas no repertório da semana da equipe."""
    repo = get_semana_repo()
    usuario_id = extract_user_id(authorization)
    resolved_equipe_id = verify_user_in_team(equipe_id, usuario_id)
    try:
        if data and data.strip():
            return _call_repo(repo.listar_por_data, data.strip(), equipe_id=resolved_equipe_id)
        if data_inicio and data_fim and data_inicio.strip() and data_fim.strip():
            return _call_repo(repo.listar_por_intervalo_datas, data_inicio.strip(), data_fim.strip(), equipe_id=resolved_equipe_id)
        return _call_repo(repo.listar_todas, equipe_id=resolved_equipe_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao consultar escala da semana: {exc}") from exc


@app.post("/api/repertorio-semana", status_code=201)
def adicionar_repertorio_semana(
    payload: RepertorioSemanaCreatePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Agenda uma música para o repertório da semana da equipe."""
    repo = get_semana_repo()
    usuario_id = extract_user_id(authorization)
    resolved_equipe_id = verify_user_in_team(payload.equipe_id, usuario_id)

    # Identificar o nome do usuário se autenticado
    adicionado_por = payload.adicionado_por
    if not adicionado_por and usuario_id:
        try:
            user_doc = get_users_repo().buscar_por_id(usuario_id)
            if user_doc and user_doc.get("nome"):
                adicionado_por = user_doc.get("nome")
        except Exception:
            pass

    try:
        scheduled_doc = _call_repo(
            repo.agendar_musica,
            musica_id=payload.musica_id,
            titulo=payload.titulo,
            cantor_principal=payload.cantor_principal,
            tom_selecionado=payload.tom_selecionado,
            data_ensaio=payload.data_ensaio,
            dia_semana=payload.dia_semana,
            versao=payload.versao or "Original",
            adicionado_por=adicionado_por or "Equipe",
            usuario_id=usuario_id,
            equipe_id=resolved_equipe_id,
        )
        dispatch_team_event(
            resolved_equipe_id,
            "weekly_changed",
            {"action": "added", "titulo": payload.titulo},
            exclude_user_id=usuario_id,
        )
        return scheduled_doc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao agendar música na semana: {exc}") from exc


@app.delete("/api/repertorio-semana/{item_id}")
def remover_repertorio_semana(
    item_id: str,
    titulo: Optional[str] = Query(default=None, description="Título da música para fallback de remoção"),
    data_ensaio: Optional[str] = Query(default=None, description="Data do ensaio YYYY-MM-DD para fallback"),
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe para fallback"),
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Remove uma música da escala da semana."""
    repo = get_semana_repo()
    try:
        sucesso = _call_repo(repo.remover_musica_escala, item_id, titulo=titulo, data_ensaio=data_ensaio)
        if not sucesso:
            raise HTTPException(status_code=404, detail="Item da escala não encontrado.")
        dispatch_team_event(
            equipe_id,
            "weekly_changed",
            {"action": "deleted", "item_id": item_id},
        )
        return {"deleted": True, "id": item_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Erro ao remover da escala: {exc}") from exc


# =============================================================================
# ROTAS DE MÚSICAS A ENSAIAR (PRÓXIMO ENSAIO)
# =============================================================================

@app.get("/api/a-ensaiar")
def listar_a_ensaiar(
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe"),
    authorization: Optional[str] = Header(default=None),
) -> list[dict[str, Any]]:
    """Retorna todas as músicas sugeridas para o próximo ensaio da equipe."""
    repo = get_a_ensaiar_repo()
    usuario_id = extract_user_id(authorization)
    resolved_equipe_id = verify_user_in_team(equipe_id, usuario_id)
    try:
        return _call_repo(repo.listar_todas, equipe_id=resolved_equipe_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao listar músicas a ensaiar: {exc}") from exc


@app.post("/api/a-ensaiar", status_code=201)
def adicionar_a_ensaiar(
    payload: MusicaAEnsaiarCreatePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Adiciona uma música sugerida para ser ensaiada pela equipe no próximo ensaio."""
    repo = get_a_ensaiar_repo()
    usuario_id = extract_user_id(authorization)
    resolved_equipe_id = verify_user_in_team(payload.equipe_id, usuario_id)

    adicionado_por = payload.adicionado_por
    if not adicionado_por and usuario_id:
        try:
            user_doc = get_users_repo().buscar_por_id(usuario_id)
            if user_doc and user_doc.get("nome"):
                adicionado_por = user_doc.get("nome")
        except Exception:
            pass

    try:
        doc = _call_repo(
            repo.adicionar_musica,
            titulo=payload.titulo,
            cantor_versao=payload.cantor_versao,
            youtube_url=payload.youtube_url or "",
            status="Próximo Ensaio",
            adicionado_por=adicionado_por or "Equipe",
            usuario_id=usuario_id,
            equipe_id=resolved_equipe_id,
        )
        dispatch_team_event(
            resolved_equipe_id,
            "to_rehearse_changed",
            {"action": "added", "titulo": payload.titulo},
            exclude_user_id=usuario_id,
        )
        return doc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao adicionar música a ensaiar: {exc}") from exc


@app.delete("/api/a-ensaiar/{item_id}")
def remover_a_ensaiar(
    item_id: str,
    titulo: Optional[str] = Query(default=None, description="Título da música para fallback de remoção"),
    cantor_versao: Optional[str] = Query(default=None, description="Cantor / Versão para fallback de remoção"),
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe para fallback"),
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Remove uma música da fila a ensaiar (ou após ser ensaiada com sucesso)."""
    repo = get_a_ensaiar_repo()
    try:
        try:
            sucesso = repo.remover_musica(
                item_id,
                titulo=titulo,
                cantor_versao=cantor_versao,
                equipe_id=equipe_id,
            )
        except TypeError:
            sucesso = repo.remover_musica(item_id)
        if not sucesso:
            raise HTTPException(status_code=404, detail="Música a ensaiar não encontrada.")
        dispatch_team_event(
            equipe_id,
            "to_rehearse_changed",
            {"action": "deleted", "item_id": item_id},
        )
        return {"deleted": True, "id": item_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Erro ao remover música a ensaiar: {exc}") from exc


# =============================================================================
# ROTAS DE MULTI-EQUIPES, CONVITES E PING ("CHAMAR MÚSICO")
# =============================================================================

@app.get("/api/equipe/minhas-equipes")
def listar_minhas_equipes(authorization: Optional[str] = Header(default=None)) -> list[dict[str, Any]]:
    """Lista todas as equipes das quais o usuário autenticado faz parte."""
    usuario_id = extract_user_id(authorization)
    if not usuario_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticação necessária.")
    equipes_repo = get_equipes_repo()
    try:
        return equipes_repo.listar_equipes_do_usuario(usuario_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao listar equipes: {exc}") from exc


@app.post("/api/equipe/criar", status_code=status.HTTP_201_CREATED)
def criar_equipe(
    payload: EquipeCreatePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Cria uma nova equipe com código de convite único."""
    usuario_id = extract_user_id(authorization)
    if not usuario_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticação necessária.")
    users_repo = get_users_repo()
    user_doc = users_repo.buscar_por_id(usuario_id)
    criador_nome = (user_doc.get("nome") if user_doc else None) or "Músico"

    equipes_repo = get_equipes_repo()
    try:
        return equipes_repo.criar_equipe(
            nome=payload.nome,
            criado_por_id=usuario_id,
            criado_por_nome=criador_nome,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao criar equipe: {exc}") from exc


@app.post("/api/equipe/entrar")
def entrar_equipe(
    payload: EquipeEntrarPayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Entra em uma equipe através de seu código de convite."""
    usuario_id = extract_user_id(authorization)
    if not usuario_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticação necessária.")
    equipes_repo = get_equipes_repo()
    try:
        return equipes_repo.entrar_equipe_por_codigo(codigo=payload.codigo, usuario_id=usuario_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao entrar na equipe: {exc}") from exc


@app.get("/api/equipe/membros")
def listar_membros_equipe(
    equipe_id: Optional[str] = Query(default=None, description="ID da equipe selecionada"),
    authorization: Optional[str] = Header(default=None),
) -> list[dict[str, Any]]:
    """Lista todos os músicos/usuários cadastrados na equipe ativa."""
    usuario_id = extract_user_id(authorization)
    resolved_equipe_id = verify_user_in_team(equipe_id, usuario_id)
    equipes_repo = get_equipes_repo()
    try:
        membros = equipes_repo.listar_membros_equipe(resolved_equipe_id)
        if usuario_id:
            membros = [m for m in membros if str(m.get("_id") or m.get("id")) != str(usuario_id)]
        return membros
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao listar membros da equipe: {exc}") from exc


@app.post("/api/equipe/ping", status_code=status.HTTP_201_CREATED)
def enviar_ping(
    payload: PingCreatePayload,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    """Dispara uma notificação/ping de chamada para outro músico da equipe (cooldown 10s)."""
    usuario_id = extract_user_id(authorization)
    if not usuario_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticação necessária para chamar.")
    resolved_equipe_id = verify_user_in_team(payload.equipe_id, usuario_id)

    users_repo = get_users_repo()
    remetente = users_repo.buscar_por_id(usuario_id)
    remetente_nome = (remetente.get("nome") if remetente else None) or "Músico da equipe"

    pings_repo = get_pings_repo()
    try:
        ping_result = pings_repo.enviar_ping(
            remetente_id=usuario_id,
            remetente_nome=remetente_nome,
            destinatario_id=payload.destinatario_id,
            destinatario_nome=payload.destinatario_nome or "",
            equipe_id=resolved_equipe_id,
        )
        dispatch_team_event(
            resolved_equipe_id,
            "team_ping",
            {
                "remetente_nome": remetente_nome,
                "destinatario_id": payload.destinatario_id,
                "destinatario_nome": payload.destinatario_nome or "",
            },
            exclude_user_id=usuario_id,
        )
        return ping_result
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao disparar chamada: {exc}") from exc


@app.get("/api/equipe/meus-pings")
def buscar_meus_pings(
    equipe_id: Optional[str] = Query(default=None),
    authorization: Optional[str] = Header(default=None),
) -> list[dict[str, Any]]:
    """Busca chamadas/pings pendentes endereçados ao usuário autenticado."""
    usuario_id = extract_user_id(authorization)
    if not usuario_id:
        return []

    pings_repo = get_pings_repo()
    try:
        return pings_repo.buscar_pings_pendentes(usuario_id, equipe_id=equipe_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao buscar chamadas: {exc}") from exc


@app.post("/api/equipe/ping/{ping_id}/lido")
def marcar_ping_lido(ping_id: str, authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """Marca um ping como visualizado/lido para não notificar repetidamente."""
    pings_repo = get_pings_repo()
    try:
        sucesso = pings_repo.marcar_como_lido(ping_id)
        return {"status": "ok", "ping_id": ping_id, "lido": sucesso}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Erro ao marcar ping como lido: {exc}") from exc


# =============================================================================
# MONTAGEM FLET WEB (PWA) VIA FLET.FASTAPI E ARQUIVOS ESTÁTICOS
# =============================================================================
# Compatibilidade Flet Web 1.0.4 + FastAPI >= 0.115 (elimina conflito de openapi_prefix)
_orig_fastapi_init = FastAPI.__init__
def _compat_fastapi_init(self, *args: Any, **kwargs: Any) -> None:
    kwargs.pop("openapi_prefix", None)
    return _orig_fastapi_init(self, *args, **kwargs)
FastAPI.__init__ = _compat_fastapi_init

# Exposição explícita de ícones e assets estáticos para evitar ERR_CONNECTION_REFUSED
base_dir = os.path.dirname(os.path.abspath(__file__))
icons_dir = os.path.join(base_dir, "assets", "icons")
if os.path.exists(icons_dir):
    app.mount("/icons", StaticFiles(directory=icons_dir), name="icons")

assets_dir = os.path.join(base_dir, "assets")
if os.path.exists(assets_dir):
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

try:
    import flet.fastapi as flet_fastapi

    from ciphersong.ui.app_flet import build_ciphersong_app

    # Compatibilidade com Flet 1.0+ para suportar session_handler=
    _orig_flet_app = flet_fastapi.app
    def _compat_flet_app(*args: Any, **kwargs: Any) -> Any:
        if "session_handler" in kwargs and "main" not in kwargs:
            kwargs["main"] = kwargs.pop("session_handler")
        return _orig_flet_app(*args, **kwargs)
    flet_fastapi.app = _compat_flet_app

    # Monta a aplicação Flet Web exatamente na raiz ("/")
    flet_web_app = flet_fastapi.app(
        session_handler=build_ciphersong_app,
        assets_dir="assets",
    )

    # A montagem na raiz "/" é estritamente a última rota registrada no FastAPI
    app.mount("/", flet_web_app)
    logger.info("CipherSong Flet Web montado com sucesso na rota raiz '/'.")
except Exception as _flet_mount_err:
    logger.error("Falha ao montar Flet Web no FastAPI: %s", _flet_mount_err, exc_info=True)
    raise _flet_mount_err



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend_api:app", host="0.0.0.0", port=8000, reload=False)
