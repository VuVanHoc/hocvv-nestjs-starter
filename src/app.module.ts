import { Module, ValidationPipe } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from './prisma/prisma.module';
import { APP_PIPE } from '@nestjs/core';

@Module({
	imports: [
		UserModule,
		AuthModule,
		ConfigModule.forRoot({ isGlobal: true }),
		PrismaModule,
	],
	controllers: [AppController],
	providers: [
		AppService,
		{
			provide: APP_PIPE,
			useValue: new ValidationPipe({
				transform: true,
				whitelist: true,
				forbidNonWhitelisted: true,
			}),
		},
	],
})
export class AppModule {}
