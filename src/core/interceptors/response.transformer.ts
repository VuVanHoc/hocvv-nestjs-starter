import {
	CallHandler,
	ExecutionContext,
	HttpStatus,
	Injectable,
	NestInterceptor,
} from '@nestjs/common';
import { Observable, map } from 'rxjs';
import { DataResponse, MessageResponse } from '../http/response';

@Injectable()
export class ResponseTransformer implements NestInterceptor {
	intercept(_: ExecutionContext, next: CallHandler): Observable<any> {
		return next.handle().pipe(
			map((data) => {
				if (data instanceof MessageResponse) return data;
				if (data instanceof DataResponse) return data;
				if (typeof data == 'string')
					return new MessageResponse(HttpStatus.OK, data);
				return new DataResponse(HttpStatus.OK, 'success', data);
			}),
		);
	}
}
