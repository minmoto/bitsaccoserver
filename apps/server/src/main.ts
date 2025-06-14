import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { ApiModule } from './api';

async function bootstrap() {
  const app = await NestFactory.create(ApiModule);

  // Get ConfigService after app is created
  const configService = app.get(ConfigService);

  // Configure logging based on environment
  const nodeEnv = configService.get<string>('NODE_ENV');
  const logLevels =
    nodeEnv === 'development'
      ? (['log', 'debug', 'error', 'verbose', 'warn'] as const)
      : (['log', 'error', 'warn'] as const);

  app.useLogger([...logLevels]);

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // CORS configuration
  const corsOrigin = configService.get<string>('CORS_ORIGIN');
  app.enableCors({
    origin: corsOrigin?.split(',') || '*',
    credentials: true,
  });

  // Global prefix
  app.setGlobalPrefix('api/v1');

  // Swagger configuration
  const config = new DocumentBuilder()
    .setTitle('Bitsaccoserver API')
    .setDescription(
      'Multi-tenant API management for Bitsacco Server\n\n' +
        '## Authentication\n\n' +
        'This API supports two authentication methods:\n\n' +
        '### 1. JWT Bearer Token (Recommended for testing)\n' +
        '1. Call `POST /auth/login` with your credentials\n' +
        '2. Copy the `access_token` from the response\n' +
        '3. Click the **Authorize** button above\n' +
        '4. Paste the token in the **Bearer Token** field\n' +
        '5. All subsequent API calls will be authenticated\n\n' +
        '### 2. API Key\n' +
        '1. Create an organization and API key via the authenticated endpoints\n' +
        '2. Use the `x-api-key` header for service-to-service authentication\n\n' +
        "**Note**: Public endpoints like `/health` and auth endpoints don't require authentication.",
    )
    .setVersion('1.0')
    .addBearerAuth({
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
      name: 'JWT',
      description: 'Enter JWT token (get it from /auth/login)',
      in: 'header',
    })
    .addApiKey(
      {
        type: 'apiKey',
        name: 'x-api-key',
        in: 'header',
        description: 'API Key for service-to-service authentication',
      },
      'api-key',
    )
    .build();

  // Swagger setup - only enabled in development/staging, never in production
  const isProduction = nodeEnv === 'production';

  if (!isProduction) {
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/docs', app, document, {
      swaggerOptions: {
        persistAuthorization: true,
        displayOperationId: false,
        displayRequestDuration: true,
        docExpansion: 'none',
        filter: true,
        showExtensions: true,
        showCommonExtensions: true,
        tryItOutEnabled: true,
      },
      customSiteTitle: 'Bitsaccoserver API Documentation',
      customfavIcon: '/favicon.ico',
    });
  }

  const port = configService.get<number>('PORT');
  await app.listen(port);

  const logger = new Logger('Bootstrap');
  logger.log(`🚀 Console is running on: http://localhost:${port}/api/v1`);

  if (!isProduction) {
    logger.log(`📚 API Documentation: http://localhost:${port}/api/docs`);
  }
}

bootstrap();
