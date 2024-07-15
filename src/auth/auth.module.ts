import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UserService } from 'src/user/user.service';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaModule } from 'src/prisma/prisma.module';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from './guards/auth.guard';
import { RolesGuard } from './guards/roles.guard';

@Module({
	providers: [
		AuthService,
		UserService,
		JwtService,
		ConfigService,
		{
			provide: APP_GUARD,
			useClass: AuthGuard,
		},
		{ provide: APP_GUARD, useClass: RolesGuard },
	],
	controllers: [AuthController],
	imports: [PrismaModule],
})
export class AuthModule {}
