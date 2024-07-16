import { Module, ValidationPipe } from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core';
import { ResponseTransformer } from './interceptors/response.transformer';
import { ConfigModule } from '@nestjs/config';
import { ResponseValidation } from './interceptors/response-validation.interceptor';
import { ExceptionHandler } from './interceptors/exception.handler';

@Module({
	imports: [ConfigModule],
	providers: [
		{ provide: APP_INTERCEPTOR, useClass: ResponseTransformer },
		{ provide: APP_INTERCEPTOR, useClass: ResponseValidation },
		{ provide: APP_FILTER, useClass: ExceptionHandler },
		{
			provide: APP_PIPE,
			useValue: new ValidationPipe({
				transform: true,
				whitelist: true,
				forbidNonWhitelisted: true,
			}),
		},
	],
	controllers: [],
})
export class CoreModule {}
