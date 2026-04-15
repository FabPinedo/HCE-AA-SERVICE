import { Controller, Post, Get, Body, Headers, Req, Res, UnauthorizedException } from '@nestjs/common';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';

const COOKIE_ACCESS = 'access_token';

function extractToken(req: Request, authHeader: string | undefined): string {
  // Primero intenta cookie, luego Authorization header
  const fromCookie = req.cookies?.[COOKIE_ACCESS];
  if (fromCookie) return fromCookie;
  if (!authHeader?.startsWith('Bearer ')) throw new UnauthorizedException('Token requerido');
  return authHeader.replace('Bearer ', '').trim();
}

@Controller('auth')
export class AuthController {
  private readonly cookieSecure: boolean;

  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
  ) {
    // COOKIE_SECURE=true solo cuando el frontend accede al AG via HTTPS
    // Si el AG sirve solo HTTP, debe ser false aunque NODE_ENV=production
    this.cookieSecure = (config.get<string>('COOKIE_SECURE') ?? process.env['COOKIE_SECURE']) === 'true';
  }

  private setCookies(res: Response, accessToken: string) {
    res.cookie(COOKIE_ACCESS, accessToken, {
      httpOnly: true,
      secure:   this.cookieSecure,
      sameSite: 'lax' as const,
      path:     '/',
      maxAge:   4 * 60 * 60 * 1000, // 4h — igual al tiempo de vida del mac_token
    });
  }

  private clearCookies(res: Response) {
    res.clearCookie(COOKIE_ACCESS, { path: '/' });
  }

  @Post('login')
  async login(
    @Body() body: { username: string; password: string },
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.login(body.username, body.password, {
      ip:        (req.headers['x-forwarded-for'] as string) ?? req.ip,
      userAgent: req.headers['user-agent'],
      traceId:   req.headers['x-trace-id'] as string,
    });
    this.setCookies(res, result.data.access_token);
    return result;
  }

  @Post('validate')
  validate(@Req() req: Request, @Headers('authorization') authHeader: string) {
    return this.authService.validateToken(extractToken(req, authHeader));
  }

  @Post('logout')
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Headers('authorization') authHeader: string,
  ) {
    const token = extractToken(req, authHeader);
    const result = await this.authService.cerrarSesionMac(token, {
      traceId: req.headers['x-trace-id'] as string,
    });
    this.clearCookies(res);
    return result;
  }

  @Get('me')
  getMe(@Req() req: Request, @Headers('authorization') authHeader: string) {
    return this.authService.getMe(extractToken(req, authHeader));
  }

  @Get('accesos')
  getAccesos(@Req() req: Request, @Headers('authorization') authHeader: string) {
    return this.authService.getAccesos(extractToken(req, authHeader));
  }

  @Post('cambiar-contrasena')
  cambiarContrasena(
    @Req() req: Request,
    @Headers('authorization') authHeader: string,
    @Body() body: { actualContrasena: string; nuevaContrasena: string },
  ) {
    return this.authService.cambiarContrasena(extractToken(req, authHeader), body.actualContrasena, body.nuevaContrasena);
  }

  @Get('health')
  health() {
    return { status: 'OK', service: 'auth-pruebas-auth', timestamp: new Date().toISOString() };
  }
}
