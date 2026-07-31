import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { firstValueFrom } from 'rxjs';

export interface ProxyResult {
  status: number;
  data: any;
}

/**
 * Cliente HTTP hacia `ms-bs-core-security` a través de `apigw-bs-hce`.
 *
 * Mismo patrón que PatientProxyHttpRepository en ms-cnl-web-hce-patients:
 * HttpService + BS_GATEWAY_URL de ConfigService + rutas bajo /api/v1/,
 * `validateStatus: () => true` para que el DAO decida qué hacer con cada status
 * en vez de que axios lance.
 *
 * DIFERENCIA con ese patrón: aquí no hay headers de request de usuario que
 * reenviar. `IAuthDao.validateUser()` corre ANTES de que exista una sesión, e
 * `IMacAuthDao.*` recibe solo (macToken, codigoPerfil) — la firma no incluye el
 * request. Por eso cada llamada se autentica con un JWT de SERVICIO de corta vida
 * (`scope: 'security:internal'`, secreto JWT_SECRET_SERVICE), el mismo mecanismo
 * que ya usa el gateway para emergency-monitor/public.
 */
@Injectable()
export class SecurityProxyHttpRepository {
  private readonly logger = new Logger(SecurityProxyHttpRepository.name);
  private readonly baseUrl: string;
  private readonly serviceSecret: string;
  private readonly serviceTokenTtl: string;

  constructor(
    private readonly http: HttpService,
    private readonly jwt: JwtService,
    cfg: ConfigService,
  ) {
    this.baseUrl = cfg.get<string>('BS_GATEWAY_URL', 'http://localhost:10604');
    this.serviceSecret = cfg.get<string>('JWT_SECRET_SERVICE', cfg.get<string>('JWT_SECRET', ''));
    this.serviceTokenTtl = cfg.get<string>('SERVICE_TOKEN_TTL', '60s');
    if (!this.serviceSecret) {
      this.logger.error('JWT_SECRET_SERVICE no configurado — las llamadas a ms-bs-core-security serán rechazadas por el gateway');
    }
  }

  private url(path: string): string {
    return `${this.baseUrl}/api/v1/${path}`;
  }

  /**
   * Token de servicio efímero. Se firma por llamada en vez de cachearse: con TTL de
   * 60s el ahorro de cachear es marginal y un token en memoria compartida sería una
   * credencial de larga vida más que vigilar.
   */
  private headers(): Record<string, string> {
    const token = this.jwt.sign(
      { sub: 'ms-cnl-cross-auth-profile', scope: 'security:internal' },
      { secret: this.serviceSecret, expiresIn: this.serviceTokenTtl as any },
    );
    return { Authorization: `Bearer ${token}` };
  }

  async post(path: string, body: any): Promise<ProxyResult> {
    const r = await firstValueFrom(
      this.http.post(this.url(path), body, { headers: this.headers(), validateStatus: () => true }),
    );
    return { status: r.status, data: r.data };
  }

  async get(path: string, params?: Record<string, any>): Promise<ProxyResult> {
    const r = await firstValueFrom(
      this.http.get(this.url(path), { headers: this.headers(), params, validateStatus: () => true }),
    );
    return { status: r.status, data: r.data };
  }

  // ── security/auth (solo existe si la instancia corre con AUTH_MODE=local) ──

  login(username: string, password: string, context?: { ip?: string; userAgent?: string }): Promise<ProxyResult> {
    return this.post('security/auth/login', { username, password, ip: context?.ip, userAgent: context?.userAgent });
  }

  accesos(macToken: string, codigoPerfil: string): Promise<ProxyResult> {
    return this.get('security/auth/accesos', { macToken, codigoPerfil });
  }

  logout(macToken: string, codigoUsuario: string): Promise<ProxyResult> {
    return this.post('security/auth/logout', { macToken, codigoUsuario });
  }

  cambiarContrasena(macToken: string, codigoUsuario: string, actualContrasena: string, nuevaContrasena: string): Promise<ProxyResult> {
    return this.post('security/auth/cambiar-contrasena', { macToken, codigoUsuario, actualContrasena, nuevaContrasena });
  }

  // ── security/ui (existe SIEMPRE, con y sin MAC) ──

  /** Decorator de §9.7: devuelve el mismo árbol con `campos` inyectado por nodo vista. */
  decorarAccesos(opciones: any[], codigoPerfil: string): Promise<ProxyResult> {
    return this.post('security/ui/accesos/decorar', { opciones, codigoPerfil });
  }

  /** §9.6: fila única `tenant_branding` de ESTE tenant — autoritativa, MAC no la conoce. */
  tenantBranding(): Promise<ProxyResult> {
    return this.get('security/ui/tenant-branding');
  }
}
