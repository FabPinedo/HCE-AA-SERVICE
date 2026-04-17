import { Controller, Post, Get, Body, Req, Res, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiCookieAuth } from '@nestjs/swagger';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { LoginDto, CambiarContrasenaDto } from './login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

const COOKIE_ACCESS = 'access_token';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  private readonly cookieSecure: boolean;
  private readonly cookieMaxAge: number;

  constructor(
    private readonly authService: AuthService,
    private readonly config:      ConfigService,
  ) {
    this.cookieSecure = config.get<string>('COOKIE_SECURE', 'false') === 'true';
    this.cookieMaxAge = this.parseDuration(config.get<string>('JWT_EXPIRES_IN', '4h'));
  }

  private parseDuration(raw: string): number {
    const match = raw.match(/^(\d+)(s|m|h|d)$/);
    if (!match) return 4 * 3_600_000;
    const multipliers: Record<string, number> = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 };
    return Number(match[1]) * (multipliers[match[2]] ?? 3_600_000);
  }

  private setCookies(res: Response, accessToken: string): void {
    res.cookie(COOKIE_ACCESS, accessToken, {
      httpOnly: true,
      secure:   this.cookieSecure,
      sameSite: 'lax' as const,
      path:     '/',
      maxAge:   this.cookieMaxAge,
    });
  }

  private clearCookies(res: Response): void {
    res.clearCookie(COOKIE_ACCESS, { path: '/' });
  }

  // ── Rutas públicas ─────────────────────────────────────────────

  @ApiOperation({ summary: 'Login — retorna JWT en cookie httpOnly y en body' })
  @Post('login')
  async login(
    @Body() body: LoginDto,
    @Req()  req:  Request,
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

  @ApiOperation({ summary: 'Valida un JWT — usado internamente por el API Gateway' })
  @Post('validate')
  validate(@Req() req: Request) {
    const cookieToken = (req.cookies as any)?.['access_token'] as string | undefined;
    const authHeader  = req.headers['authorization'] as string | undefined;
    const token = cookieToken ?? (authHeader?.replace('Bearer ', '').trim() ?? '');
    return this.authService.validateToken(token);
  }

  @ApiOperation({ summary: 'Health check' })
  @Get('health')
  health() {
    return { status: 'OK', service: 'auth-pruebas-auth', timestamp: new Date().toISOString() };
  }

  // ── Rutas protegidas (requieren JWT válido) ────────────────────

  @ApiOperation({ summary: 'Datos del usuario autenticado (desde JWT, sin DB lookup)' })
  @ApiBearerAuth()
  @ApiCookieAuth('access_token')
  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@Req() req: Request) {
    return this.authService.getMe(req['user']);
  }

  @ApiOperation({ summary: 'Árbol de accesos del usuario en MAC' })
  @ApiBearerAuth()
  @ApiCookieAuth('access_token')
  @UseGuards(JwtAuthGuard)
  @Get('accesos')
  getAccesos(@Req() req: Request) {
    return this.authService.getAccesos(req['user']);
  }

  @ApiOperation({ summary: 'Cierra sesión en MAC y limpia la cookie' })
  @ApiBearerAuth()
  @ApiCookieAuth('access_token')
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.cerrarSesionMac(req['user'], {
      traceId: req.headers['x-trace-id'] as string,
    });
    this.clearCookies(res);
    return result;
  }

  @ApiOperation({ summary: 'Cambio de contraseña vía MAC' })
  @ApiBearerAuth()
  @ApiCookieAuth('access_token')
  @UseGuards(JwtAuthGuard)
  @Post('cambiar-contrasena')
  cambiarContrasena(
    @Req()  req:  Request,
    @Body() body: CambiarContrasenaDto,
  ) {
    return this.authService.cambiarContrasena(req['user'], body.actualContrasena, body.nuevaContrasena);
  }
}
