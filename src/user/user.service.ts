import {
	Injectable,
	NotFoundException,
	UnauthorizedException,
} from '@nestjs/common';
import { Prisma, User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { ErrorEnum } from 'src/enums/errors.enum';
import { JwtService } from '@nestjs/jwt';
import { UserDto } from './dtos/user.dto';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UserService {
	constructor(
		private prismaService: PrismaService,
		private jwtService: JwtService,
		private configService: ConfigService,
	) {}

	async user(
		userWhereUniqueInput: Prisma.UserWhereUniqueInput,
	): Promise<User | null> {
		return this.prismaService.user.findUnique({
			where: userWhereUniqueInput,
		});
	}

	async users(params: {
		skip?: number;
		take?: number;
		cursor?: Prisma.UserWhereUniqueInput;
		where?: Prisma.UserWhereInput;
		orderBy?: Prisma.UserOrderByWithRelationInput;
	}): Promise<User[]> {
		const { skip, take, cursor, where, orderBy } = params;
		return this.prismaService.user.findMany({
			skip,
			take,
			cursor,
			where,
			orderBy,
		});
	}

	async createUser(data: Prisma.UserCreateInput): Promise<User> {
		return this.prismaService.user.create({
			data,
		});
	}

	async updateUser(params: {
		where: Prisma.UserWhereUniqueInput;
		data: Prisma.UserUpdateInput;
	}): Promise<User> {
		const { where, data } = params;
		return this.prismaService.user.update({
			data,
			where,
		});
	}

	async deleteUser(where: Prisma.UserWhereUniqueInput): Promise<User> {
		return this.prismaService.user.delete({
			where,
		});
	}

	async isMatchPassword(
		password: string,
		hashPassword: string,
	): Promise<boolean> {
		return await bcrypt.compare(password, hashPassword);
	}

	async getSignedInUserByUsername(username: string): Promise<UserDto> {
		const user = await this.prismaService.user.findFirst({
			where: {
				username,
			},
		});
		if (!user) {
			throw new NotFoundException(ErrorEnum.USER_NOT_FOUND);
		}
		if (!user.refreshToken) {
			throw new UnauthorizedException(ErrorEnum.TOKEN_EXPRIED);
		}
		try {
			// Verify refreshToken. If pass -> return user
			await this.jwtService.verifyAsync(user.refreshToken, {
				secret: this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET'),
			});
		} catch (error: any) {
			if (error.name === 'TokenExpiredError') {
				// Verify refreshToken. If not pass -> throw error & FORCE LOGOUT
				throw new UnauthorizedException(ErrorEnum.TOKEN_EXPRIED);
			}
		}
		const userDto = new UserDto(user);
		return userDto;
	}

	async saveRefreshToken(id: number, refreshToken: string) {
		const user = await this.prismaService.user.findUnique({
			where: {
				id,
			},
		});
		if (!user) {
			throw new NotFoundException(ErrorEnum.USER_NOT_FOUND);
		}
		user.refreshToken = refreshToken;
		return this.prismaService.user.update({
			where: {
				id,
			},
			data: {
				refreshToken,
			},
		});
	}
}
