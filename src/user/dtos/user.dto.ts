import { Role } from '@prisma/client';

export class UserDto {
	constructor(user: any) {
		this.id = user.id;
		this.username = user.username;
		this.email = user.email;
		this.roles = user.roles;
	}
	id: string;
	username: string;
	email: string;
	roles: Role;
}
