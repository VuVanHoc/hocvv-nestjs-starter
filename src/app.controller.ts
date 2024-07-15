import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { Public } from './auth/decorators/public.decorator';
import { Roles } from './auth/decorators/role.decorator';
import { Role } from '@prisma/client';
import { UserService } from './user/user.service';
import * as bcrypt from 'bcrypt';
import { ApiBearerAuth } from '@nestjs/swagger';

@ApiBearerAuth()
@Controller()
export class AppController {
	constructor(
		private readonly appService: AppService,
		private userService: UserService,
	) {}

	// Public endpoint, don't need token
	@Public()
	@Get()
	getHello(): string {
		return this.appService.getHello();
	}

	// Only user with role ADMIN can access
	@Roles([Role.ADMIN])
	@Get('admin')
	admin() {
		return 'admin';
	}

	// Only user with role USER can access
	@Roles([Role.USER])
	@Get('user')
	user() {
		return 'user';
	}

	// User with every role can access
	@Get('all')
	@ApiBearerAuth()
	all() {
		return 'all';
	}

	@Public()
	@Get('seed-data')
	async seedData() {
		return this.userService.createUser({
			username: 'admin',
			password: await bcrypt.hash('admin', 10),
			refreshToken: '',
			role: Role.ADMIN,
		});
	}
}
