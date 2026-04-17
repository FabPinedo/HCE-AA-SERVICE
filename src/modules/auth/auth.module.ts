import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { HttpModule } from '@nestjs/axios';
import { AuthController }       from './auth.controller';
import { AuthService }          from './auth.service';
import { ExternalAuthDao }      from './external-auth.dao';
import { MacTokenCacheService } from './mac-token-cache.service';
import { JwtAuthGuard }         from './guards/jwt-auth.guard';
import { AUTH_DAO, MAC_DAO }    from './auth-dao.interface';
import { KafkaLoggerModule }    from '../../logger/kafka-logger.module';

@Module({
  imports: [
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
      }),
      inject: [ConfigService],
    }),
    KafkaLoggerModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    ExternalAuthDao,
    MacTokenCacheService,
    JwtAuthGuard,
    { provide: AUTH_DAO, useClass: ExternalAuthDao },
    { provide: MAC_DAO,  useClass: ExternalAuthDao },
  ],
})
export class AuthModule {}
