import type { UserInfo } from '../models/user-info.interface';

/**
 * AUTH_DAO — token para IAuthDao (validación de credenciales).
 * Toda implementación (local, MAC, LDAP) debe cumplir este contrato.
 */
export const AUTH_DAO = Symbol('AUTH_DAO');

/**
 * MAC_DAO — token para IMacAuthDao (accesos, cierre de sesión, cambio de contraseña).
 *
 * Implementaciones registradas hoy, según AUTH_MODE (ver app.module.ts):
 *   - AUTH_MODE=mac   → ScreenFieldDecoratingMacAuthDao, que envuelve a ExternalAuthDao
 *                       (MAC sigue siendo la fuente del árbol) y le agrega `campos` (§9.7)
 *   - AUTH_MODE=local → LocalSecurityAuthDao, respaldado por HCE_SECURITY vía
 *                       ms-bs-core-security
 *
 * Separación por ISP: el stub AuthDao (auth.dao.ts, autenticación contra variables de
 * entorno) implementa solo IAuthDao y no está obligado a proveer estas operaciones.
 */
export const MAC_DAO = Symbol('MAC_DAO');

/**
 * Contrato base — validateUser es la única operación que toda implementación debe proveer.
 */
export interface IAuthDao {
  validateUser(username: string, password: string): Promise<UserInfo | null>;
}

/**
 * Contrato extendido para integración con MAC (Módulo de Autenticación Centralizado).
 * Implementado únicamente por ExternalAuthDao.
 * AuthDao (local/env) NO implementa esta interfaz — cumple ISP y LSP.
 */
export interface IMacAuthDao {
  getAccesos(macToken: string, codigoPerfil: string): Promise<any>;
  cerrarSesion(macToken: string, codigoUsuario: string): Promise<any>;
  cambiarContrasena(macToken: string, codigoUsuario: string, actual: string, nueva: string): Promise<any>;
}
