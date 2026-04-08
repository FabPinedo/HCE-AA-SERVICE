import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  ServiceUnavailableException,
  GatewayTimeoutException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom, timeout, TimeoutError } from 'rxjs';
import * as https from 'https';
import { createCipheriv } from 'crypto';
import type { UserInfo, Sucursal } from './user-info.interface';

/**
 * ExternalAuthDao — integración con MAC (Módulo de Autenticación Centralizado)
 *
 * Algoritmo de encriptación: AES-256-CBC / PKCS7 / Base64
 * Equivalente al Criptography.Encrypt() del sistema HCE (.NET)
 * Keys configuradas en .env: CRYPTO_KEY (32 bytes) y CRYPTO_IV (16 bytes)
 */
@Injectable()
export class ExternalAuthDao {
  private readonly logger      = new Logger(ExternalAuthDao.name);
  private readonly MAX_RETRIES = 1;
  // Códigos MAC que indican usuario bloqueado/inactivo — ajustar según documentación de MAC
  private readonly BLOCKED_CODES = new Set([2, 5]);
  private readonly RETRY_DELAY = 500;
  private get TIMEOUT_MS(): number {
    return Number(this.config.get<string>('EXTERNAL_AUTH_TIMEOUT_MS') ?? process.env['EXTERNAL_AUTH_TIMEOUT_MS'] ?? '5000');
  }
  private readonly httpsAgent: https.Agent;

  constructor(
    private readonly http:   HttpService,
    private readonly config: ConfigService,
  ) {
    // SSL_VERIFY=false acepta certificados autofirmados o de CA interna
    const sslVerify = this.config.get<string>('SSL_VERIFY', 'true') !== 'false';
    this.httpsAgent = new https.Agent({ rejectUnauthorized: sslVerify });

    // Diagnóstico de arranque — confirma que las variables de entorno se leen correctamente
    this.logger.log(`BASE_URL = ${this.baseUrl || '⚠️ VACÍO'}`);
    this.logger.log(`SSL_VERIFY = ${sslVerify}`);
    this.logger.log(`CRYPTO_KEY length = ${(this.config.get('CRYPTO_KEY') ?? process.env['CRYPTO_KEY'] ?? '').length}`);

    if (!this.baseUrl) {
      this.logger.error('EXTERNAL_AUTH_BASE_URL no está configurado — el servicio de autenticación no funcionará');
    }
  }

  private get baseUrl(): string {
    return this.config.get<string>('EXTERNAL_AUTH_BASE_URL') ?? process.env['EXTERNAL_AUTH_BASE_URL'] ?? '';
  }

  async validateUser(username: string, password: string): Promise<UserInfo | null> {
    if (!this.baseUrl) {
      throw new ServiceUnavailableException('Servicio de autenticación no configurado (EXTERNAL_AUTH_BASE_URL vacío)');
    }
    const endpoint = `${this.baseUrl}/autenticar`;

    for (let attempt = 0; attempt <= this.MAX_RETRIES; attempt++) {
      try {
        const response = await firstValueFrom(
          this.http
            .post(endpoint, this.buildBody(username, password), { httpsAgent: this.httpsAgent })
            .pipe(timeout({ each: this.TIMEOUT_MS })),
        );
        this.logger.debug(`MAC response: ${JSON.stringify(response.data)}`);
        return this.mapUser(response.data, username);

      } catch (err: any) {
        const isLast = attempt === this.MAX_RETRIES;

        if (err?.response?.status === 400 || err?.response?.status === 401 || err?.response?.status === 403) {
          this.logger.warn(`MAC rejected credentials: HTTP ${err.response.status}`);
          throw new UnauthorizedException('Credenciales inválidas');
        }
        if (err?.response?.status === 404) {
          this.logger.error(`MAC endpoint not found (404) — verificar EXTERNAL_AUTH_BASE_URL en .env`);
          throw new ServiceUnavailableException('Servicio de autenticación mal configurado (ruta no encontrada)');
        }
        if (err instanceof TimeoutError || err?.code === 'ECONNABORTED') {
          this.logger.warn(`MAC timeout (attempt ${attempt + 1})`);
          if (isLast) throw new GatewayTimeoutException('Servicio de autenticación no responde (timeout)');
          await this.delay(this.RETRY_DELAY);
          continue;
        }
        if (err?.code === 'ECONNREFUSED' || err?.code === 'ENOTFOUND' || err?.code === 'ECONNRESET') {
          this.logger.error(`MAC unreachable: ${err.code}`);
          throw new ServiceUnavailableException('Servicio de autenticación no disponible');
        }
        if (err?.response?.status >= 500) {
          this.logger.warn(`MAC error ${err.response.status} (attempt ${attempt + 1})`);
          if (isLast) throw new ServiceUnavailableException('Error en servicio de autenticación');
          await this.delay(this.RETRY_DELAY);
          continue;
        }
        if (err?.message === 'Invalid URL' || err?.code === 'ERR_INVALID_URL') {
          this.logger.error('MAC URL inválida — verificar EXTERNAL_AUTH_BASE_URL en .env');
          throw new ServiceUnavailableException('Servicio de autenticación no configurado');
        }
        this.logger.error(`Unexpected MAC error: ${err?.message}`);
        if (isLast) throw new ServiceUnavailableException('Error inesperado en autenticación');
        await this.delay(this.RETRY_DELAY);
      }
    }
    return null;
  }

  async getAccesos(macToken: string, codigoPerfil: string): Promise<any> {
    const res = await firstValueFrom(
      this.http.post(
        `${this.baseUrl}/obtenerAccesos`,
        { codigoSistema: this.config.get<string>('EXTERNAL_AUTH_SISTEMA', '25'), codigoPerfil },
        { httpsAgent: this.httpsAgent, headers: { Authorization: `bearer ${macToken}` } },
      ).pipe(timeout({ each: this.TIMEOUT_MS })),
    );
    return res.data;
  }

  async cerrarSesion(macToken: string, codigoUsuario: string): Promise<any> {
    const res = await firstValueFrom(
      this.http.post(
        `${this.baseUrl}/cerrarSesion`,
        { codigoUsuario },
        { httpsAgent: this.httpsAgent, headers: { Authorization: `bearer ${macToken}` } },
      ).pipe(timeout({ each: this.TIMEOUT_MS })),
    );
    return res.data;
  }

  async cambiarContrasena(macToken: string, codigoUsuario: string, actualContrasena: string, nuevaContrasena: string): Promise<any> {
    const res = await firstValueFrom(
      this.http.post(
        `${this.baseUrl}/cambioContrasena`,
        {
          codigoUsuario,
          actualContrasena: this.macEncrypt(actualContrasena),
          nuevaContrasena:  this.macEncrypt(nuevaContrasena),
        },
        { httpsAgent: this.httpsAgent, headers: { Authorization: `bearer ${macToken}` } },
      ).pipe(timeout({ each: this.TIMEOUT_MS })),
    );
    return res.data;
  }

  /**
   * Body para POST /autenticar de MAC.
   * La contraseña se encripta con AES-256-CBC igual que Criptography.Encrypt() en .NET.
   */
  private buildBody(username: string, password: string): Record<string, any> {
    return {
      codigoSistema: this.config.get<string>('EXTERNAL_AUTH_SISTEMA', '25'),
      codigoUsuario: username,
      contrasena:    this.macEncrypt(password),
    };
  }

  /**
   * Mapea la respuesta de MAC a UserInfo.
   * MAC responde (real): { codigo, mensaje, data: { token: { token }, usuario: { codigoUsuario, idPerfil, correo, ... } } }
   * codigo = 0 → éxito, codigo = 8 → éxito pero requiere cambio de contraseña
   */
  private mapUser(res: any, username: string): UserInfo | null {
    const codigo  = Number(res?.codigo ?? res?.Codigo ?? -1);
    const mensaje = res?.mensaje ?? res?.Mensaje ?? '';

    if (this.BLOCKED_CODES.has(codigo)) {
      this.logger.warn(`MAC blocked user: codigo=${codigo} mensaje=${mensaje} username=${username}`);
      throw new ForbiddenException(`Usuario bloqueado: ${mensaje}`);
    }

    if (codigo !== 0 && codigo !== 8) {
      this.logger.warn(`MAC rejected login: codigo=${codigo} mensaje=${mensaje}`);
      return null;
    }

    const token   = res?.data?.token?.token ?? '';
    const usuario = res?.data?.usuario ?? {};
    const perfil  = String(usuario?.idPerfil ?? '').trim();

    // CP0014 — Usuario sin roles: MAC aceptó pero no asignó perfil
    if (!perfil) {
      this.logger.warn(`MAC login sin perfil asignado para usuario: ${username}`);
      return null;
    }

    const roles: string[] = [perfil];

    const nombres         = usuario?.nombres         ?? '';
    const apellidoPaterno = usuario?.apellidoPaterno ?? '';
    const apellidoMaterno = usuario?.apellidoMaterno ?? '';

    const rawSucursales: any[] = res?.data?.sucursales ?? [];
    const sucursales: Sucursal[] = rawSucursales.map((s: any) => ({
      idSede:      String(s?.idSede ?? '').trim(),
      descripcion: String(s?.descripcion ?? '').trim(),
    }));

    return {
      userId:          usuario?.codigoUsuario ?? username,
      username:        (usuario?.codigoUsuario ?? username).toUpperCase(),
      roles,
      email:           usuario?.correo ?? usuario?.email ?? '',
      idUsuario:       String(usuario?.idUsuario ?? '').trim(),
      nombres,
      apellidoPaterno,
      apellidoMaterno,
      nombreCompleto:  `${nombres} ${apellidoPaterno} ${apellidoMaterno}`.trim(),
      nombrePerfil:    usuario?.nombrePerfil ?? '',
      numeroDocumento: usuario?.numeroDocumento ?? '',
      sucursales,
      macToken:        token,
      perfil,
    };
  }

  /**
   * AES-256-CBC + PKCS7 + Base64
   * Equivalente exacto de Criptography.Encrypt() (.NET)
   * CRYPTO_KEY: 32 bytes UTF-8 | CRYPTO_IV: 16 bytes UTF-8
   */
  private macEncrypt(text: string): string {
    try {
      const cryptoKey = this.config.get<string>('CRYPTO_KEY') ?? process.env['CRYPTO_KEY'] ?? '';
      const cryptoIv  = this.config.get<string>('CRYPTO_IV')  ?? process.env['CRYPTO_IV']  ?? '';

      if (!text)      throw new Error('password is empty or undefined');
      if (cryptoKey.length !== 32) throw new Error(`CRYPTO_KEY must be 32 chars, got ${cryptoKey.length}`);
      if (cryptoIv.length  !== 16) throw new Error(`CRYPTO_IV must be 16 chars, got ${cryptoIv.length}`);

      const key    = Buffer.from(cryptoKey, 'utf8');
      const iv     = Buffer.from(cryptoIv,  'utf8');
      const cipher = createCipheriv('aes-256-cbc', key, iv);
      const encrypted = Buffer.concat([
        cipher.update(Buffer.from(text, 'utf8')),
        cipher.final(),
      ]);
      return encrypted.toString('base64');
    } catch (e: any) {
      this.logger.error(`Encrypt error: ${e.message}`);
      throw new ServiceUnavailableException('Error al procesar credenciales');
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
