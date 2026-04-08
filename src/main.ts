import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { logger: ['log', 'warn', 'error', 'debug'] });

  app.use(cookieParser());

  // credentials:true permite que el browser envíe cookies en peticiones cross-origin
  const allowedOrigins = (process.env['CORS_ORIGINS'] ?? 'http://localhost:5173,http://localhost:10100').split(',');
  app.enableCors({
    origin:      allowedOrigins,
    credentials: true,
    methods:     ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  });

  const port = Number(process.env['PORT'] ?? 10101);
  await app.listen(port);
  console.log(`🔐 auth-pruebas-auth running on http://localhost:${port}`);
}
bootstrap();
