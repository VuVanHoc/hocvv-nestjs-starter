import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { UserService } from 'src/user/user.service';
import { Public } from './decorators/public.decorator';
import { LoginRequestDto } from './dtos/login-request.dto';
import { LoginResponseDto } from './dtos/login-response.dto';
import { Auth } from './decorators/auth.decorator';
import { User } from '@prisma/client';
import { UserDto } from 'src/user/dtos/user.dto';

@Controller('auth')
@ApiBearerAuth()
@ApiTags('Auth')
export class AuthController {
	constructor(
		private readonly authService: AuthService,
		private readonly userService: UserService,
	) {}

	@Public()
	@Post('login')
	login(@Body() loginDto: LoginRequestDto): Promise<LoginResponseDto> {
		return this.authService.login(loginDto);
	}

	@Get('me')
	authMe(@Auth() user: User): Promise<UserDto> {
		return this.userService.getSignedInUserByUsername(user.username);
	}

	@Public()
	@Get('refresh')
	refreshAccessToken(
		@Query('refreshToken') refreshToken: string,
	): Promise<{ accessToken: string }> {
		return this.authService.refreshAccessToken(refreshToken);
	}
}
