import { Injectable, UnauthorizedException, ForbiddenException, HttpException, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'crypto';
import { AUTH_DAO, IAuthDao, MAC_DAO, IMacAuthDao } from './auth-dao.interface';
import { MacTokenCacheService } from './mac-token-cache.service';
import { KafkaLoggerService } from '../../logger/kafka-logger.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwt:         JwtService,
    private readonly config:      ConfigService,
    @Inject(AUTH_DAO) private readonly authDao:   IAuthDao,
    @Inject(MAC_DAO)  private readonly macDao:    IMacAuthDao,
    private readonly macCache:    MacTokenCacheService,
    private readonly kafkaLogger: KafkaLoggerService,
  ) {}

  async login(username: string, password: string, context?: { ip?: string; userAgent?: string; traceId?: string }) {
    const attemptTraceId = context?.traceId ?? randomUUID();

    try {
      const user = await this.authDao.validateUser(username, password);
      if (!user) {
        await this.kafkaLogger.log({
          event_type: 'LOGIN_FAILED', level: 'WARN', trace_id: attemptTraceId,
          username, action: 'LOGIN', outcome: 'FAILED', reason: 'INVALID_CREDENTIALS',
          ip_address: context?.ip, user_agent: context?.userAgent,
        });
        throw new UnauthorizedException('Credenciales inválidas');
      }

      const sessionId            = randomUUID();
      const requirePasswordChange = user.requirePasswordChange ?? false;

      // mac_token almacenado en caché server-side — nunca en el JWT
      if (user.macToken) {
        this.macCache.set(sessionId, user.macToken, user.perfil ?? '');
      }

      const payload = {
        sub:             user.userId,
        username:        user.username,
        roles:           user.roles,
        email:           user.email,
        sessionId,
        idUsuario:       user.idUsuario       ?? '',
        nombres:         user.nombres         ?? '',
        apellidoPaterno: user.apellidoPaterno ?? '',
        apellidoMaterno: user.apellidoMaterno ?? '',
        nombreCompleto:  user.nombreCompleto  ?? '',
        nombrePerfil:    user.nombrePerfil    ?? '',
        numeroDocumento: user.numeroDocumento ?? '',
        sucursales:      user.sucursales      ?? [],
      };

      const accessToken = this.jwt.sign(payload);

      await this.kafkaLogger.log({
        event_type: 'LOGIN_SUCCESS', level: 'INFO', trace_id: attemptTraceId,
        user_id: user.userId, username: user.username, session_id: sessionId,
        action: 'LOGIN', outcome: 'SUCCESS',
        ip_address: context?.ip, user_agent: context?.userAgent,
      });

      return {
        success: true,
        message: requirePasswordChange ? 'Login exitoso, se requiere cambio de contraseña' : 'Login exitoso',
        data: {
          user:                 { userId: user.userId, username: user.username, roles: user.roles, email: user.email, sucursales: user.sucursales ?? [] },
          access_token:         accessToken,
          expires_in:           this.config.get<string>('JWT_EXPIRES_IN', '4h'),
          token_type:           'Bearer',
          session_id:           sessionId,
          requirePasswordChange,
        },
      };
    } catch (err) {
      if (err instanceof HttpException) throw err;   // cubre UnauthorizedException y ForbiddenException
      if (err instanceof ForbiddenException) {
        await this.kafkaLogger.log({
          event_type: 'LOGIN_BLOCKED', level: 'WARN', trace_id: attemptTraceId,
          username, action: 'LOGIN', outcome: 'BLOCKED', reason: 'USER_BLOCKED',
          ip_address: context?.ip, user_agent: context?.userAgent,
        });
        throw err;
      }
      await this.kafkaLogger.log({
        event_type: 'LOGIN_FAILED', level: 'ERROR', trace_id: attemptTraceId,
        username, action: 'LOGIN', outcome: 'ERROR', reason: (err as any)?.message,
        ip_address: context?.ip, user_agent: context?.userAgent,
      });
      throw err;
    }
  }

  /** Recibe el payload ya verificado por JwtAuthGuard */
  getMe(user: any) {
    return {
      success: true,
      data: {
        userId:          user.sub,
        username:        user.username,
        email:           user.email,
        roles:           user.roles,
        idUsuario:       user.idUsuario,
        nombres:         user.nombres,
        apellidoPaterno: user.apellidoPaterno,
        apellidoMaterno: user.apellidoMaterno,
        nombreCompleto:  user.nombreCompleto,
        nombrePerfil:    user.nombrePerfil,
        numeroDocumento: user.numeroDocumento,
        sucursales:      user.sucursales ?? [],
        sessionId:       user.sessionId,
      },
    };
  }

  /** Recibe el payload ya verificado por JwtAuthGuard */
  async getAccesos(user: any) {
    const cached = this.macCache.get(user.sessionId);
    if (!cached) throw new UnauthorizedException('Sesión MAC no encontrada o expirada');
    const raw      = await this.macDao.getAccesos(cached.macToken, cached.perfil);
    const opciones = raw?.data?.opciones ?? [];
    return {
      success: true,
      data: {
        opciones,
        permisos: this.flattenOpciones(opciones),
      },
    };
  }

  /** Recibe el payload ya verificado por JwtAuthGuard */
  async cerrarSesionMac(user: any, context?: { traceId?: string }) {
    const cached = this.macCache.get(user.sessionId);
    if (cached) {
      try {
        await this.macDao.cerrarSesion(cached.macToken, user.username);
        this.macCache.delete(user.sessionId);
      } catch (macErr: any) {
        await this.kafkaLogger.log({
          event_type: 'LOGOUT', level: 'WARN', trace_id: context?.traceId,
          user_id: user.sub, username: user.username, session_id: user.sessionId,
          action: 'LOGOUT', outcome: 'MAC_ERROR', reason: macErr?.message,
        });
      }
    }

    await this.kafkaLogger.log({
      event_type: 'LOGOUT', level: 'INFO', trace_id: context?.traceId,
      user_id: user.sub, username: user.username, session_id: user.sessionId,
      action: 'LOGOUT', outcome: 'SUCCESS',
    });

    return { success: true, message: 'Sesión cerrada correctamente' };
  }

  /** Recibe el payload ya verificado por JwtAuthGuard */
  async cambiarContrasena(user: any, actualContrasena: string, nuevaContrasena: string) {
    const cached = this.macCache.get(user.sessionId);
    if (!cached) throw new UnauthorizedException('Sesión MAC no encontrada o expirada');
    const result = await this.macDao.cambiarContrasena(cached.macToken, user.username, actualContrasena, nuevaContrasena);
    await this.kafkaLogger.log({
      event_type: 'PASSWORD_CHANGE', level: 'INFO',
      user_id: user.sub, username: user.username, session_id: user.sessionId,
      action: 'PASSWORD_CHANGE', outcome: 'SUCCESS',
    });
    return result;
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

  /**
   * Equivalente a LlenarOpcionesRecursivo() de UtilSeguridad.vb (.NET)
   */
  private flattenOpciones(opciones: any[]): Array<{ codigo: string; titulo: string; indicador: string }> {
    const result: Array<{ codigo: string; titulo: string; indicador: string }> = [];
    for (const op of opciones) {
      result.push({
        codigo:    String(op.codigo    ?? '').trim(),
        titulo:    String(op.titulo    ?? '').trim(),
        indicador: String(op.indicador ?? '').trim(),
      });
      if (op.opciones?.length) result.push(...this.flattenOpciones(op.opciones));
    }
    return result;
  }
}
