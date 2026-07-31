import { Injectable, Logger } from '@nestjs/common';
import type { IMacAuthDao } from '../../domain/repositories/auth-dao.interface';
import { SecurityProxyHttpRepository } from './security-proxy.http.repository';

/**
 * Patrón decorator de §9.7 — lado ms-cnl, para tenants CON MAC (Clínica San Felipe).
 *
 * COMPOSICIÓN, no herencia: recibe el `IMacAuthDao` real (`ExternalAuthDao`) en el
 * constructor y lo envuelve. `ExternalAuthDao` NO SE TOCA — sigue siendo el cliente
 * HTTP hacia el .NET legado y la única fuente de verdad del árbol de menú. Meter la
 * consulta a `HCE_SECURITY` dentro de esa clase mezclaría "hablar con MAC" con
 * "consultar la base local": dos responsabilidades, dos fuentes de datos.
 *
 * Flujo:
 *   1. `ExternalAuthDao.getAccesos()` → árbol {opciones} tal como MAC lo entrega hoy
 *   2. `ms-bs-core-security` POST /security/ui/accesos/decorar → mismo árbol con
 *      `campos: [{codigo, indicador}]` agregado a cada nodo tipo vista
 *   3. `AuthUseCase.getAccesos()` sigue sin cambios: `campos` es un array anidado y
 *      `flattenOpciones()` no lo toca.
 *
 * `cerrarSesion` y `cambiarContrasena` se delegan sin decorar: no devuelven árbol.
 */
@Injectable()
export class ScreenFieldDecoratingMacAuthDao implements IMacAuthDao {
  private readonly logger = new Logger(ScreenFieldDecoratingMacAuthDao.name);

  constructor(
    private readonly inner: IMacAuthDao,
    private readonly proxy: SecurityProxyHttpRepository,
  ) {}

  async getAccesos(macToken: string, codigoPerfil: string): Promise<any> {
    // Paso 1 — el legado manda. Si esto falla, falla toda la operación (igual que hoy).
    const raw = await this.inner.getAccesos(macToken, codigoPerfil);

    const opciones = raw?.data?.opciones;
    if (!Array.isArray(opciones) || !opciones.length || !codigoPerfil?.trim()) return raw;

    // Paso 2 — la decoración es BEST-EFFORT a propósito: si HCE_SECURITY no responde,
    // el usuario debe seguir entrando con el árbol de MAC intacto. Sin `campos`, el
    // frontend aplica el default de §4.3 (todo visible), que es exactamente el estado
    // que tenía la plataforma antes de que esta capa existiera. Degradar a "no ve
    // nada" por una base de configuración caída sería mucho peor que degradar a
    // "ve todo", que es el comportamiento previo conocido.
    try {
      const res = await this.proxy.decorarAccesos(opciones, codigoPerfil);
      if (res.status < 200 || res.status >= 300) {
        this.logger.warn(`Decorador de campos respondió ${res.status} — se devuelve el árbol de MAC sin decorar`);
        return raw;
      }
      // ResponseInterceptor del ms-bs envuelve: { data: { data: { opciones } } }
      const decoradas = res.data?.data?.data?.opciones ?? res.data?.data?.opciones ?? res.data?.opciones;
      if (!Array.isArray(decoradas)) {
        this.logger.warn('Respuesta del decorador con forma inesperada — se devuelve el árbol de MAC sin decorar');
        return raw;
      }
      // Se reemplaza solo `opciones`, preservando el resto del sobre de MAC
      // (codigo, mensaje, y cualquier campo que MAC agregue a futuro).
      return { ...raw, data: { ...raw.data, opciones: decoradas } };
    } catch (err: any) {
      this.logger.warn(`Fallo al decorar campos (${err?.message}) — se devuelve el árbol de MAC sin decorar`);
      return raw;
    }
  }

  cerrarSesion(macToken: string, codigoUsuario: string): Promise<any> {
    return this.inner.cerrarSesion(macToken, codigoUsuario);
  }

  cambiarContrasena(macToken: string, codigoUsuario: string, actual: string, nueva: string): Promise<any> {
    return this.inner.cambiarContrasena(macToken, codigoUsuario, actual, nueva);
  }
}
