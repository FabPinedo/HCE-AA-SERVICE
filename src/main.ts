import { NestFactory }    from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule }      from './app.module';
import * as cookieParser  from 'cookie-parser';
import helmet             from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { logger: ['log', 'warn', 'error', 'debug'] });

  app.use(helmet());
  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));

  // Sin CORS — este servicio solo recibe requests del API Gateway (red interna),
  // nunca directamente desde el browser.

  // Swagger — disponible en /api/docs (solo fuera de producción)
  if (process.env['NODE_ENV'] !== 'production') {
    const doc = new DocumentBuilder()
      .setTitle('Auth Service — aa-pruebas-auth')
      .setDescription('Microservicio de autenticación JWT + integración MAC')
      .setVersion('1.0')
      .addBearerAuth()
      .addCookieAuth('access_token')
      .build();
    SwaggerModule.setup('api/docs', app, SwaggerModule.createDocument(app, doc));
  }

  const port = Number(process.env['PORT'] ?? 10101);
  await app.listen(port);
  console.log(`🔐 auth-pruebas-auth  → http://localhost:${port}`);
  if (process.env['NODE_ENV'] !== 'production') {
    console.log(`📄 Swagger docs       → http://localhost:${port}/api/docs`);
  }
}
bootstrap();
