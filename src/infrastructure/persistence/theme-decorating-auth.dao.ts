import { Injectable, Logger } from '@nestjs/common';
import type { IAuthDao } from '../../domain/repositories/auth-dao.interface';
import type { UserInfo } from '../../domain/models/user-info.interface';
import { SecurityProxyHttpRepository } from './security-proxy.http.repository';

/**
 * Patrón decorator de §9.6 — para tenants CON MAC (Clínica San Felipe).
 *
 * `ExternalAuthDao` NO SE TOCA: no tiene ni puede tener noción de `theme_code`,
 * que vive únicamente en `HCE_SECURITY.tenant_branding` (nunca en MAC/AD). Mismo
 * razonamiento que `ScreenFieldDecoratingMacAuthDao` para `campos` en getAccesos():
 * composición sobre el DAO real, no una rama dentro de él.
 *
 * Sin este decorator, `AuthUseCase.login()` firmaría siempre `themeCode: ''` para
 * un tenant con MAC — el flujo de §9.6 (tema autoritativo, firmado en el JWT)
 * quedaría roto precisamente para el tenant que hoy existe.
 */
@Injectable()
export class ThemeDecoratingAuthDao implements IAuthDao {
  private readonly logger = new Logger(ThemeDecoratingAuthDao.name);

  constructor(
    private readonly inner: IAuthDao,
    private readonly proxy: SecurityProxyHttpRepository,
  ) {}

  async validateUser(username: string, password: string): Promise<UserInfo | null> {
    // Paso 1 — el legado manda. Si MAC rechaza o falla, no hay nada que decorar.
    const user = await this.inner.validateUser(username, password);
    if (!user) return user;

    // Paso 2 — best-effort, igual que el decorator de campos: si HCE_SECURITY no
    // responde, el login debe seguir funcionando. Sin themeCode, el frontend cae
    // al tema por defecto del design system — degradación aceptable, un login
    // bloqueado por una base de branding caída no lo es.
    try {
      const res = await this.proxy.tenantBranding();
      if (res.status < 200 || res.status >= 300) {
        this.logger.warn(`tenant-branding respondió ${res.status} — login continúa sin themeCode`);
        return user;
      }
      const themeCode = res.data?.data?.theme_code ?? res.data?.theme_code;
      if (!themeCode) {
        this.logger.warn('tenant-branding sin theme_code en la respuesta — login continúa sin themeCode');
        return user;
      }
      return { ...user, themeCode };
    } catch (err: any) {
      this.logger.warn(`Fallo al resolver themeCode (${err?.message}) — login continúa sin themeCode`);
      return user;
    }
  }
}
