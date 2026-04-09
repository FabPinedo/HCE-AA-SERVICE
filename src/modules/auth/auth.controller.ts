import { Controller, Post, Get, Body, Headers, Req, Res, UnauthorizedException } from '@nestjs/common';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';

const COOKIE_ACCESS  = 'access_token';
const COOKIE_REFRESH = 'refresh_token';

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

  private setCookies(res: Response, accessToken: string, refreshToken: string) {
    const cookieOpts = {
      httpOnly: true,
      secure:   this.cookieSecure,
      sameSite: 'lax' as const,
      path:     '/',
    };
    res.cookie(COOKIE_ACCESS,  accessToken,  { ...cookieOpts, maxAge: 4  * 60 * 60 * 1000 }); // 4h
    res.cookie(COOKIE_REFRESH, refreshToken, { ...cookieOpts, maxAge: 7  * 24 * 60 * 60 * 1000 }); // 7d
  }

  private clearCookies(res: Response) {
    res.clearCookie(COOKIE_ACCESS,  { path: '/' });
    res.clearCookie(COOKIE_REFRESH, { path: '/' });
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
    this.setCookies(res, result.data.access_token, result.data.refresh_token);
    return result;
  }

  @Post('refresh')
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies?.[COOKIE_REFRESH] ?? req.body?.refresh_token;
    if (!refreshToken) throw new UnauthorizedException('Refresh token requerido');
    const result = await this.authService.refresh(refreshToken, {
      traceId: req.headers['x-trace-id'] as string,
    });
    res.cookie(COOKIE_ACCESS, result.data.access_token, {
      httpOnly: true,
      secure:   this.cookieSecure,
      sameSite: 'lax',
      path:     '/',
      maxAge:   4 * 60 * 60 * 1000,
    });
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
