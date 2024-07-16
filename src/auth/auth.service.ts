import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import { LoginRequestDto } from './dtos/login-request.dto';
import { LoginResponseDto } from './dtos/login-response.dto';
import { ErrorEnum } from 'src/enums/errors.enum';
import { PrismaService } from 'src/prisma/prisma.service';
import { User } from '@prisma/client';

@Injectable()
export class AuthService {
	constructor(
		private userService: UserService,
		private jwtService: JwtService,
		private configService: ConfigService,
		private prismaService: PrismaService,
	) {}
	async login(loginDto: LoginRequestDto): Promise<LoginResponseDto> {
		const { username, password } = loginDto;
		const user = await this.prismaService.user.findFirst({
			where: {
				username,
			},
		});

		if (!user) {
			throw new UnauthorizedException(ErrorEnum.USER_NOT_FOUND);
		}
		const matchPassword = await this.userService.isMatchPassword(
			password,
			user.password,
		);
		if (!matchPassword) {
			throw new UnauthorizedException(ErrorEnum.WRONG_PASSWORD);
		}

		const loginResponseDto = new LoginResponseDto();
		const accessToken = await this.generateToken(
			user,
			this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
			this.configService.get('JWT_ACCESS_TOKEN_EXPIRED'),
		);
		const refreshToken = await this.generateToken(
			user,
			this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
			this.configService.get('JWT_REFRESH_TOKEN_EXPRIED'),
		);
		loginResponseDto.accessToken = accessToken;
		loginResponseDto.refreshToken = refreshToken;

		await this.userService.saveRefreshToken(user.id, refreshToken);
		return loginResponseDto;
	}

	async generateToken(
		user: User,
		secret: string,
		expiresIn: string,
	): Promise<string> {
		const payload = {
			username: user.username,
			id: user.id,
			roles: [user.role],
		};
		const accessToken = await this.jwtService.signAsync(payload, {
			secret,
			expiresIn,
		});
		return accessToken;
	}

	async refreshAccessToken(
		refreshToken: string,
	): Promise<{ accessToken: string }> {
		if (!refreshToken) {
			throw new UnauthorizedException(ErrorEnum.TOKEN_EXPRIED);
		}
		try {
			const payload = await this.jwtService.verifyAsync(refreshToken, {
				secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
			});
			if (!payload) {
				throw new UnauthorizedException(ErrorEnum.TOKEN_EXPRIED);
			}
			const user = await this.prismaService.user.findFirst({
				where: {
					username: payload.username,
				},
			});
			const accessToken = await this.generateToken(
				user,
				this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
				this.configService.get('JWT_ACCESS_TOKEN_EXPIRED'),
			);
			return {
				accessToken,
			};
		} catch (error: any) {
			throw new UnauthorizedException(ErrorEnum.TOKEN_EXPRIED);
		}
	}
}
