import { Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'crypto';
import { ExternalAuthDao } from './external-auth.dao';
import { KafkaLoggerService } from '../../logger/kafka-logger.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwt:    JwtService,
    private readonly config: ConfigService,
    private readonly dao:    ExternalAuthDao,
    private readonly kafkaLogger: KafkaLoggerService,
  ) {}

  async login(username: string, password: string, context?: { ip?: string; userAgent?: string; traceId?: string }) {
    // ── Intento de login — registrar ANTES de validar ────────────
    const attemptTraceId = context?.traceId ?? randomUUID();

    try {
      const user = await this.dao.validateUser(username, password);
      if (!user) {
        await this.kafkaLogger.log({
          event_type: 'LOGIN_FAILED',
          level:      'WARN',
          trace_id:   attemptTraceId,
          username,
          action:     'LOGIN',
          outcome:    'FAILED',
          reason:     'INVALID_CREDENTIALS',
          ip_address: context?.ip,
          user_agent: context?.userAgent,
        });
        throw new UnauthorizedException('Credenciales inválidas');
      }

      const sessionId = randomUUID();
      const payload   = {
        sub:              user.userId,
        username:         user.username,
        roles:            user.roles,
        email:            user.email,
        sessionId,
        // Datos de display — disponibles via /auth/me sin DB lookup
        idUsuario:        user.idUsuario        ?? '',
        nombres:          user.nombres          ?? '',
        apellidoPaterno:  user.apellidoPaterno  ?? '',
        apellidoMaterno:  user.apellidoMaterno  ?? '',
        nombreCompleto:   user.nombreCompleto   ?? '',
        nombrePerfil:     user.nombrePerfil     ?? '',
        numeroDocumento:  user.numeroDocumento  ?? '',
        sucursales:       user.sucursales       ?? [],
        ...(user.macToken ? { mac_token: user.macToken, mac_perfil: user.perfil } : {}),
      };

      const accessToken  = this.jwt.sign(payload);
      const refreshToken = this.jwt.sign(
        { sub: user.userId, username: user.username, sessionId },
        { secret: this.config.get<string>('JWT_REFRESH_SECRET'), expiresIn: this.config.get<string>('JWT_REFRESH_EXPIRES_IN', '7d') } as any,
      );

      await this.kafkaLogger.log({
        event_type: 'LOGIN_SUCCESS',
        level:      'INFO',
        trace_id:   attemptTraceId,
        user_id:    user.userId,
        username:   user.username,
        session_id: sessionId,
        action:     'LOGIN',
        outcome:    'SUCCESS',
        ip_address: context?.ip,
        user_agent: context?.userAgent,
      });

      return {
        success: true,
        message: 'Login successful',
        data: {
          user:          { userId: user.userId, username: user.username, roles: user.roles, email: user.email, sucursales: user.sucursales ?? [] },
          access_token:  accessToken,
          expires_in:    this.config.get<string>('JWT_EXPIRES_IN', '4h'),
          token_type:    'Bearer',
          refresh_token: refreshToken,
          session_id:    sessionId,
        },
      };
    } catch (err) {
      if (err instanceof UnauthorizedException) throw err;
      if (err instanceof ForbiddenException) {
        await this.kafkaLogger.log({
          event_type: 'LOGIN_BLOCKED',
          level:      'WARN',
          trace_id:   attemptTraceId,
          username,
          action:     'LOGIN',
          outcome:    'BLOCKED',
          reason:     'USER_BLOCKED',
          ip_address: context?.ip,
          user_agent: context?.userAgent,
        });
        throw err;
      }
      await this.kafkaLogger.log({
        event_type: 'LOGIN_FAILED',
        level:      'ERROR',
        trace_id:   attemptTraceId,
        username,
        action:     'LOGIN',
        outcome:    'ERROR',
        reason:     (err as any)?.message,
        ip_address: context?.ip,
        user_agent: context?.userAgent,
      });
      throw err;
    }
  }

  async refresh(refreshToken: string, context?: { traceId?: string }) {
    try {
      const decoded   = this.jwt.verify(refreshToken, { secret: this.config.get<string>('JWT_REFRESH_SECRET') }) as any;
      const sessionId = decoded.sessionId ?? randomUUID();
      const payload   = { sub: decoded.sub, username: decoded.username, roles: decoded.roles ?? [], email: decoded.email ?? '', sessionId };
      const accessToken = this.jwt.sign(payload);

      await this.kafkaLogger.log({
        event_type: 'TOKEN_REFRESH',
        level:      'INFO',
        trace_id:   context?.traceId,
        user_id:    decoded.sub,
        username:   decoded.username,
        session_id: sessionId,
        action:     'TOKEN_REFRESH',
        outcome:    'SUCCESS',
      });

      return {
        success: true, message: 'Token refreshed successfully',
        data: { access_token: accessToken, expires_in: this.config.get<string>('JWT_EXPIRES_IN', '4h'), token_type: 'Bearer', session_id: sessionId },
      };
    } catch {
      throw new UnauthorizedException('Refresh token inválido o expirado');
    }
  }

  async logout(token: string, context?: { traceId?: string }) {
    try {
      const d = this.jwt.verify(token) as any;
      await this.kafkaLogger.log({
        event_type: 'LOGOUT',
        level:      'INFO',
        trace_id:   context?.traceId,
        user_id:    d.sub,
        username:   d.username,
        session_id: d.sessionId,
        action:     'LOGOUT',
        outcome:    'SUCCESS',
      });
      return { success: true, message: 'Logout successful' };
    } catch {
      throw new UnauthorizedException('Token inválido o expirado');
    }
  }

  async getAccesos(token: string) {
    try {
      const d = this.jwt.verify(token) as any;
      if (!d.mac_token) throw new UnauthorizedException('Token de sesión sin credenciales externas');
      const raw      = await this.dao.getAccesos(d.mac_token, d.mac_perfil ?? '');
      const opciones = raw?.data?.opciones ?? [];
      return {
        success: true,
        data: {
          opciones,                              // árbol original de MAC
          permisos: this.flattenOpciones(opciones), // lista plana equivalente a ObtenerOpciones() del .NET
        },
      };
    } catch (err) {
      if (err instanceof UnauthorizedException) throw err;
      throw new UnauthorizedException('Token inválido o expirado');
    }
  }

  /**
   * Equivalente a LlenarOpcionesRecursivo() de UtilSeguridad.vb (.NET)
   * Aplana el árbol de opciones de MAC en una lista plana de { codigo, titulo, indicador }
   * Permite verificar permisos con: permisos.some(p => p.codigo === '01/01')
   */
  private flattenOpciones(opciones: any[]): Array<{ codigo: string; titulo: string; indicador: string }> {
    const result: Array<{ codigo: string; titulo: string; indicador: string }> = [];
    for (const op of opciones) {
      result.push({
        codigo:    String(op.codigo    ?? '').trim(),
        titulo:    String(op.titulo    ?? '').trim(),
        indicador: String(op.indicador ?? '').trim(),
      });
      if (op.opciones?.length) {
        result.push(...this.flattenOpciones(op.opciones));
      }
    }
    return result;
  }

  async cerrarSesionMac(token: string, context?: { traceId?: string }) {
    let d: any;
    try {
      d = this.jwt.verify(token) as any;
    } catch {
      throw new UnauthorizedException('Token inválido o expirado');
    }

    // Cerrar sesión en MAC — best-effort: no bloquea el logout si MAC falla
    if (d.mac_token) {
      try {
        await this.dao.cerrarSesion(d.mac_token, d.username);
      } catch (macErr: any) {
        // Loguear advertencia pero continuar con el logout local
        await this.kafkaLogger.log({
          event_type: 'LOGOUT',
          level:      'WARN',
          trace_id:   context?.traceId,
          user_id:    d.sub,
          username:   d.username,
          session_id: d.sessionId,
          action:     'LOGOUT',
          outcome:    'MAC_ERROR',
          reason:     macErr?.message,
        });
      }
    }

    await this.kafkaLogger.log({
      event_type: 'LOGOUT',
      level:      'INFO',
      trace_id:   context?.traceId,
      user_id:    d.sub,
      username:   d.username,
      session_id: d.sessionId,
      action:     'LOGOUT',
      outcome:    'SUCCESS',
    });

    return { success: true, message: 'Sesión cerrada correctamente' };
  }

  async cambiarContrasena(token: string, actualContrasena: string, nuevaContrasena: string) {
    try {
      const d = this.jwt.verify(token) as any;
      if (!d.mac_token) throw new UnauthorizedException('Token de sesión sin credenciales externas');
      const result = await this.dao.cambiarContrasena(d.mac_token, d.username, actualContrasena, nuevaContrasena);
      await this.kafkaLogger.log({
        event_type: 'PASSWORD_CHANGE',
        level:      'INFO',
        user_id:    d.sub,
        username:   d.username,
        session_id: d.sessionId,
        action:     'PASSWORD_CHANGE',
        outcome:    'SUCCESS',
      });
      return result;
    } catch (err) {
      if (err instanceof UnauthorizedException) throw err;
      throw new UnauthorizedException('Token inválido o expirado');
    }
  }

  async getMe(token: string) {
    try {
      const d = this.jwt.verify(token) as any;
      return {
        success: true,
        data: {
          userId:          d.sub,
          username:        d.username,
          email:           d.email,
          roles:           d.roles,
          idUsuario:       d.idUsuario,
          nombres:         d.nombres,
          apellidoPaterno: d.apellidoPaterno,
          apellidoMaterno: d.apellidoMaterno,
          nombreCompleto:  d.nombreCompleto,
          nombrePerfil:    d.nombrePerfil,
          numeroDocumento: d.numeroDocumento,
          idPerfil:        d.mac_perfil,
          sucursales:      d.sucursales ?? [],
          sessionId:       d.sessionId,
        },
      };
    } catch {
      throw new UnauthorizedException('Token inválido o expirado');
    }
  }

  async validateToken(token: string) {
    try {
      const d = this.jwt.verify(token) as any;
      return {
        success: true, message: 'Token is valid',
        data: { userId: d.sub, username: d.username, email: d.email, roles: d.roles, sessionId: d.sessionId, exp: d.exp, iat: d.iat },
      };
    } catch {
      throw new UnauthorizedException('Token inválido o expirado');
    }
  }
}
