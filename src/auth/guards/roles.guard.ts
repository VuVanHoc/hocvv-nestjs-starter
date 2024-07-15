import {
	CanActivate,
	ExecutionContext,
	ForbiddenException,
	Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Roles } from '../decorators/role.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
	constructor(private readonly reflector: Reflector) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		let roles = this.reflector.get(Roles, context.getHandler());
		if (!roles) roles = this.reflector.get(Roles, context.getClass());
		if (roles) {
			const request = context.switchToHttp().getRequest();
			const user = request.user;
			if (!user) throw new ForbiddenException('Permission Denied');

			const hasRole = () =>
				user.roles.some((role) => !!roles.find((item) => item === role));

			if (!hasRole()) throw new ForbiddenException('Permission Denied');
		}

		return true;
	}
}
