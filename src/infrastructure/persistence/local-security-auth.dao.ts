import {
  GatewayTimeoutException,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { IAuthDao, IMacAuthDao } from '../../domain/repositories/auth-dao.interface';
import type { UserInfo } from '../../domain/models/user-info.interface';
import { MacTokenExpiredException } from '../../domain/exceptions/mac-token-expired.exception';
import { SecurityProxyHttpRepository } from './security-proxy.http.repository';

/**
 * Implementación REAL de `IAuthDao` + `IMacAuthDao` respaldada por `HCE_SECURITY`,
 * vía `ms-bs-core-security` a través de `apigw-bs-hce`. Se registra en ambos tokens
 * de DI (AUTH_DAO y MAC_DAO) cuando `AUTH_MODE=local`.
 *
 * Reemplaza al stub `AuthDao` (autenticación contra variables de entorno), que se
 * conserva en `auth.dao.ts` sin cambios: sigue sirviendo como fallback de desarrollo
 * sin infraestructura, pero ya no es la única alternativa a `ExternalAuthDao`.
 *
 * Contrato de errores: `ms-bs-core-security` ya devuelve `{ codigo, mensaje }` con el
 * status HTTP equivalente al de MAC (401 para 5/6, 403 para 7/9), justamente para que
 * `AuthUseCase.login()` siga distinguiendo LOGIN_BLOCKED de LOGIN_FAILED por
 * `status === 403`. Aquí solo se re-lanzan tal cual, sin re-mapear.
 */
@Injectable()
export class LocalSecurityAuthDao implements IAuthDao, IMacAuthDao {
  private readonly logger = new Logger(LocalSecurityAuthDao.name);

  constructor(private readonly proxy: SecurityProxyHttpRepository) {}

  async validateUser(username: string, password: string): Promise<UserInfo | null> {
    const res = await this.safe(() => this.proxy.login(username, password), 'login');
    this.throwIfBusinessError(res.status, res.data, 'login');
    // ResponseInterceptor de ms-bs-* envuelve todo en { success, statusCode, message, data }.
    return (res.data?.data ?? res.data) as UserInfo;
  }

  async getAccesos(macToken: string, codigoPerfil: string): Promise<any> {
    const res = await this.safe(() => this.proxy.accesos(macToken, codigoPerfil), 'accesos');

    // 401 aquí = sesión de HCE_SECURITY revocada o expirada. Se traduce a
    // MacTokenExpiredException (mismo contrato que ExternalAuthDao) para que
    // AuthUseCase.getAccesos() limpie el macCache igual que con MAC.
    if (res.status === 401) throw new MacTokenExpiredException();
    this.throwIfBusinessError(res.status, res.data, 'accesos');

    // El use case del ms-bs devuelve { data: { opciones } } y el interceptor lo
    // envuelve otra vez → { data: { data: { opciones } } }. AuthUseCase espera
    // raw?.data?.opciones, así que se desenvuelve una capa.
    const payload = res.data?.data ?? res.data;
    return payload;
  }

  async cerrarSesion(macToken: string, codigoUsuario: string): Promise<any> {
    const res = await this.safe(() => this.proxy.logout(macToken, codigoUsuario), 'logout');
    this.throwIfBusinessError(res.status, res.data, 'logout');
    return res.data?.data ?? res.data;
  }

  async cambiarContrasena(macToken: string, codigoUsuario: string, actual: string, nueva: string): Promise<any> {
    const res = await this.safe(
      () => this.proxy.cambiarContrasena(macToken, codigoUsuario, actual, nueva),
      'cambiar-contrasena',
    );
    if (res.status === 401 && Number(res.data?.codigo) === 3) throw new MacTokenExpiredException();
    this.throwIfBusinessError(res.status, res.data, 'cambiar-contrasena');
    return res.data?.data ?? res.data;
  }

  /** Errores de red/gateway → mismas excepciones que ya usa ExternalAuthDao. */
  private async safe<T>(call: () => Promise<T>, endpoint: string): Promise<T> {
    try {
      return await call();
    } catch (err: any) {
      if (err?.code === 'ECONNABORTED') {
        this.logger.warn(`ms-bs-core-security timeout en ${endpoint}`);
        throw new GatewayTimeoutException('Servicio de seguridad no responde (timeout)');
      }
      this.logger.error(`ms-bs-core-security inalcanzable en ${endpoint}: ${err?.code ?? err?.message}`);
      throw new ServiceUnavailableException('Servicio de seguridad no disponible');
    }
  }

  private throwIfBusinessError(status: number, body: any, endpoint: string): void {
    if (status >= 200 && status < 300) return;

    // 404 con AUTH_MODE mal configurado es el error más probable en despliegue:
    // la instancia de ms-bs-core-security corre en modo mac y /security/auth/* no existe.
    if (status === 404) {
      this.logger.error(
        `ms-bs-core-security respondió 404 en ${endpoint} — verificar que esa instancia corra con AUTH_MODE=local`,
      );
      throw new ServiceUnavailableException('Servicio de seguridad mal configurado (ruta no encontrada)');
    }

    const codigo = body?.codigo ?? body?.message?.codigo;
    const mensaje = body?.mensaje ?? body?.message?.mensaje ?? body?.message ?? 'Error en servicio de seguridad';
    this.logger.warn(`ms-bs-core-security ${endpoint} error: status=${status} codigo=${codigo} mensaje=${mensaje}`);
    // Se preserva status y forma { codigo, mensaje }: AuthUseCase.login() decide
    // LOGIN_BLOCKED vs LOGIN_FAILED mirando exactamente ese status.
    throw new HttpException({ codigo, mensaje }, status || HttpStatus.SERVICE_UNAVAILABLE);
  }
}
