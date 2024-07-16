import { HttpStatus } from '@nestjs/common';

export class MessageResponse {
	readonly statusCode: HttpStatus;
	readonly message: string;

	constructor(statusCode: HttpStatus, message: string) {
		this.statusCode = statusCode;
		this.message = message;
	}
}

export class DataResponse<T> extends MessageResponse {
	readonly data: T;

	constructor(statusCode: HttpStatus, message: string, data: T) {
		super(statusCode, message);
		this.data = data;
	}
}
