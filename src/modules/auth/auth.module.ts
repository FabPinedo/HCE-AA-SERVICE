import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { HttpModule } from '@nestjs/axios';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AuthDao } from './auth.dao';
import { ExternalAuthDao } from './external-auth.dao';
import { KafkaLoggerModule } from '../../logger/kafka-logger.module';

@Module({
  imports: [
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (cfg: ConfigService) => ({
        secret: cfg.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: cfg.get<string>('JWT_EXPIRES_IN', '4h') as any },
      }),
      inject: [ConfigService],
    }),
    HttpModule.register({ timeout: 5000 }),
    KafkaLoggerModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, AuthDao, ExternalAuthDao],
})
export class AuthModule {}
