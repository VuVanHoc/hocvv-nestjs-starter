import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { PrismaModule } from 'src/prisma/prisma.module';
import { JwtService } from '@nestjs/jwt';

@Module({
	controllers: [UserController],
	providers: [UserService, JwtService],
	exports: [UserService],
	imports: [PrismaModule],
})
export class UserModule {}
