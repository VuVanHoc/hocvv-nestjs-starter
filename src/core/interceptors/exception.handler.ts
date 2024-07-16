import {
	ExceptionFilter,
	Catch,
	ArgumentsHost,
	HttpException,
	HttpStatus,
	InternalServerErrorException,
	UnauthorizedException,
	Logger,
} from '@nestjs/common';
import { TokenExpiredError } from '@nestjs/jwt';
import { Request, Response } from 'express';
import { isArray } from 'class-validator';

@Catch()
export class ExceptionHandler implements ExceptionFilter {
	private readonly logger = new Logger(ExceptionHandler.name);

	catch(exception: unknown, host: ArgumentsHost) {
		const ctx = host.switchToHttp();
		const response = ctx.getResponse<Response>();
		const request = ctx.getRequest<Request>();

		let status = HttpStatus.INTERNAL_SERVER_ERROR;
		let message: string = 'Something went wrong';
		let errors: any[] | undefined = undefined;

		if (exception instanceof HttpException) {
			status = exception.getStatus();
			const body = exception.getResponse();

			if (typeof body === 'string') {
				message = body;
			} else if ('message' in body) {
				if (typeof body.message === 'string') {
					message = body.message;
				} else if (isArray(body.message) && body.message.length > 0) {
					message = body.message[0];
					errors = body.message;
				}
			}

			if (exception instanceof InternalServerErrorException) {
				this.logger.error(exception.message, exception.stack);
			}

			if (exception instanceof UnauthorizedException) {
				if (message.toLowerCase().includes('invalid access token')) {
					status = HttpStatus.UNAUTHORIZED;
					response.header('instruction', 'logout');
				}
			}
		} else if (exception instanceof TokenExpiredError) {
			status = HttpStatus.UNAUTHORIZED;
			response.header('instruction', 'refresh_token');
			message = 'Token Expired';
		} else if (exception instanceof Error) {
			message = exception.message;
			this.logger.error(exception.message, exception.stack);
		}

		// Use send function for Fastify
		response.status(status).send({
			statusCode: status,
			message: message,
			errors: errors,
			url: request.url,
		});
	}
}
