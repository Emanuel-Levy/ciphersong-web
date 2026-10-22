# CipherSong Web (PWA)

Aplicação Web e Progressive Web App (PWA) standalone do **CipherSong**, construída com **Flet 1.0+** e **FastAPI**, pronta para deploy em nuvem (Fly.io, Render, Heroku ou Docker).

---

## 🚀 Arquitetura

- **Frontend:** Flet 1.0+ Web PWA (compatível com navegadores desktop e Safari iOS com suporte a "Adicionar à Tela de Início").
- **Backend:** FastAPI + Uvicorn com suporte a WebSockets (`/api/ws/events` e canal interno Flet `/ws`).
- **Banco de Dados:** MongoDB Atlas (`pymongo[srv]`).
- **Segurança:** Autenticação por Tokens JWT, senhas protegidas com PBKDF2-HMAC-SHA256, e cofre de sessão no navegador via `page.shared_preferences`.

---

## 🛠️ Execução Local

1. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure as variáveis de ambiente (ou utilize um arquivo `.env` local):
   ```bash
   export MONGODB_URI="sua_string_de_conexao_mongodb_atlas"
   export JWT_SECRET="sua_chave_secreta_jwt"
   ```

3. Inicie o servidor Uvicorn:
   ```bash
   python -m uvicorn backend_api:app --host 0.0.0.0 --port 8000 --reload
   ```

4. Acesse:
   - **Interface Web / PWA:** [http://localhost:8000](http://localhost:8000)
   - **Health Check da API:** [http://localhost:8000/api/health](http://localhost:8000/api/health)
   - **Documentação Swagger:** [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🐳 Deploy via Docker

Construa e execute a imagem Docker localmente:
```bash
docker build -t ciphersong-web .
docker run -p 8000:8000 -e MONGODB_URI="sua_uri" ciphersong-web
```

---

## ☁️ Deploy no Fly.io / Render

### Render
1. Crie um novo **Web Service** apontando para este repositório.
2. Selecione o ambiente **Docker**.
3. Adicione a variável de ambiente `MONGODB_URI` no painel do Render.

### Fly.io
1. Execute `fly launch` na raiz deste repositório.
2. Configure o segredo do banco:
   ```bash
   fly secrets set MONGODB_URI="sua_uri"
   ```
3. Realize o deploy:
   ```bash
   fly deploy
   ```
