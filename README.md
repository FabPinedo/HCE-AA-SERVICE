# auth-pruebas-auth

> Auth Service generado por **Jarvis Platform** — 2/4/2026

## JWT Payload (audit-ready)

```json
{
  "sub":       "uuid-del-usuario",
  "username":  "juan.perez",
  "roles":     ["admin", "user"],
  "email":     "juan@empresa.com",
  "sessionId": "uuid-de-sesion",
  "iat": 1234567890,
  "exp": 1234571490
}
```

> **sub** y **username** son leídos por el API Gateway para registrar eventos de audit.
> **sessionId** correlaciona con AUTH_SESSION en el logger.

## Integración con servicio externo

El servicio delega la autenticación a `EXTERNAL_AUTH_URL`.
Adaptar el método `mapUser()` en `external-auth.dao.ts` según el contrato del servicio externo.

### Manejo de errores

| Escenario | Comportamiento |
|-----------|----------------|
| Credenciales inválidas | `401 Unauthorized` |
| Timeout (>5s) | `504 Gateway Timeout` — 1 reintento automático |
| Servicio caído | `503 Service Unavailable` — sin reintentos |
| Error 5xx del externo | `503 Service Unavailable` — 1 reintento (500ms) |

## Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | /auth/login | Login — retorna access_token + refresh_token |
| POST | /auth/refresh | Renueva el access_token |
| POST | /auth/validate | Valida token (usado por el API Gateway) |
| POST | /auth/logout | Logout |
| GET  | /auth/health | Health check |

## Instalación

```bash
npm install
cp .env.example .env
npm run start:dev
```
