import { Logger, Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { HttpModule } from '@nestjs/axios';
import { HealthModule } from './health/health.module';
import { KafkaLoggerModule } from './logger/kafka-logger.module';
import { AuditInterceptor } from './logger/audit.interceptor';
import { AuthUseCase } from './application/use-cases/Auth.use-case';
import { AuthController } from './infrastructure/controllers/Auth.controller';
import { ExternalAuthDao } from './infrastructure/persistence/external-auth.dao';
import { SecurityProxyHttpRepository } from './infrastructure/persistence/security-proxy.http.repository';
import { LocalSecurityAuthDao } from './infrastructure/persistence/local-security-auth.dao';
import { ScreenFieldDecoratingMacAuthDao } from './infrastructure/persistence/screen-field-decorating-mac.dao';
import { ThemeDecoratingAuthDao } from './infrastructure/persistence/theme-decorating-auth.dao';
import { MacTokenCacheService } from './infrastructure/cache/mac-token-cache.service';
import { JwtAuthGuard } from './infrastructure/guards/jwt-auth.guard';
import { AUTH_DAO, MAC_DAO } from './domain/repositories/auth-dao.interface';
import { buildOutboundHttpsAgent } from './ssl/ssl-config.util';

/**
 * AUTH_MODE — decide qué implementación de IAuthDao/IMacAuthDao se registra.
 *
 * Es la MISMA variable que consume `ms-bs-core-security` para decidir si instancia
 * su AuthModule; ambos despliegues de un mismo tenant deben coincidir.
 *
 *   AUTH_MODE=mac  (default) → tenant CON MAC, ej. Clínica San Felipe
 *       AUTH_DAO = ThemeDecoratingAuthDao            (ExternalAuthDao + `themeCode`, §9.6)
 *       MAC_DAO  = ScreenFieldDecoratingMacAuthDao   (ExternalAuthDao + `campos`, §9.7)
 *       (ambos decorators envuelven la MISMA instancia de ExternalAuthDao, que
 *       sigue sin tocarse — no conoce ni theme_code ni campos, solo login/menú MAC)
 *
 *   AUTH_MODE=local          → tenant SIN MAC, HCE_SECURITY es la fuente
 *       AUTH_DAO = MAC_DAO = LocalSecurityAuthDao   (vía ms-bs-core-security)
 *
 * Se lee de process.env porque la decisión ocurre al construir el arreglo de
 * providers, antes de que exista el árbol de DI. El default es `mac` para que un
 * despliegue que no defina la variable siga comportándose EXACTAMENTE como hoy
 * (salvo por la decoración best-effort de `campos`, que degrada al árbol crudo de
 * MAC si HCE_SECURITY no responde).
 */
const AUTH_MODE = (process.env.AUTH_MODE ?? 'mac').trim().toLowerCase();
const IS_LOCAL_AUTH = AUTH_MODE === 'local';

const authDaoProviders = IS_LOCAL_AUTH
  ? [
      // useExisting (no useClass): reutiliza la instancia ya declarada abajo en vez
      // de construir una segunda — el patrón anterior con useClass creaba una copia
      // por token, inofensivo con ExternalAuthDao pero no con un DAO con estado.
      { provide: AUTH_DAO, useExisting: LocalSecurityAuthDao },
      { provide: MAC_DAO,  useExisting: LocalSecurityAuthDao },
    ]
  : [
      {
        // Composición explícita: ambos decorators envuelven la MISMA instancia de
        // ExternalAuthDao (no herencia, no se toca esa clase). AUTH_DAO decora
        // themeCode (§9.6); MAC_DAO decora campos (§9.7) — son ejes independientes,
        // por eso son dos decorators distintos y no uno que haga ambas cosas.
        provide: AUTH_DAO,
        useFactory: (inner: ExternalAuthDao, proxy: SecurityProxyHttpRepository) =>
          new ThemeDecoratingAuthDao(inner, proxy),
        inject: [ExternalAuthDao, SecurityProxyHttpRepository],
      },
      {
        provide: MAC_DAO,
        useFactory: (inner: ExternalAuthDao, proxy: SecurityProxyHttpRepository) =>
          new ScreenFieldDecoratingMacAuthDao(inner, proxy),
        inject: [ExternalAuthDao, SecurityProxyHttpRepository],
      },
    ];

@Module({
  imports: [
    HealthModule,
    ConfigModule.forRoot({ isGlobal: true }),
    JwtModule.registerAsync({
      imports:    [ConfigModule],
      useFactory: (cfg: ConfigService) => ({
        secret:      cfg.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: cfg.get<string>('JWT_EXPIRES_IN', '4h') as any },
      }),
      inject: [ConfigService],
    }),
    HttpModule.registerAsync({
      imports:    [ConfigModule],
      useFactory: (cfg: ConfigService) => ({
        timeout: Number(cfg.get<string>('EXTERNAL_AUTH_TIMEOUT_MS', '5000')),
        httpsAgent: buildOutboundHttpsAgent(),
      }),
      inject: [ConfigService],
    }),
    KafkaLoggerModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthUseCase,
    // ExternalAuthDao se declara SIEMPRE: en modo mac es el DAO real y en modo local
    // queda inerte (nadie lo inyecta). Su constructor solo loguea configuración, no
    // abre conexiones, así que declararlo condicionalmente no ahorraría nada.
    ExternalAuthDao,
    // El proxy también se declara siempre: en modo mac lo usa el decorator, en modo
    // local lo usa LocalSecurityAuthDao.
    SecurityProxyHttpRepository,
    LocalSecurityAuthDao,
    MacTokenCacheService,
    JwtAuthGuard,
    ...authDaoProviders,
    { provide: APP_INTERCEPTOR, useClass: AuditInterceptor },
  ],
})
export class AppModule {
  private readonly logger = new Logger(AppModule.name);
  constructor() {
    this.logger.log(
      IS_LOCAL_AUTH
        ? 'AUTH_MODE=local — AUTH_DAO y MAC_DAO = LocalSecurityAuthDao (ms-bs-core-security / HCE_SECURITY)'
        : `AUTH_MODE=${AUTH_MODE} — AUTH_DAO = ThemeDecoratingAuthDao (MAC), MAC_DAO = ScreenFieldDecoratingMacAuthDao`,
    );
  }
}
