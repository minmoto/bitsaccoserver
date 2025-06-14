import { Model } from 'mongoose';
import { Request, Response, NextFunction } from 'express';
import { Injectable, NestMiddleware } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import {
  TransactionLogDocument,
  TransactionType,
  TransactionStatus,
} from './schemas/transaction-log.schema';

@Injectable()
export class UsageTrackingMiddleware implements NestMiddleware {
  constructor(
    @InjectModel(TransactionLogDocument.name)
    private transactionLogModel: Model<TransactionLogDocument>,
  ) {}

  use(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();
    const originalSend = res.send;

    // Capture response data
    res.send = function (data) {
      const responseTime = Date.now() - startTime;
      const _user = (req as any).user;
      const organizationId = (req as any).organizationId;
      const apiKeyId = (req as any).apiKeyId;

      // Only track if we have organization context (authenticated requests)
      if (organizationId && req.route) {
        const logData = {
          organizationId,
          apiKeyId,
          serviceId: 'fooservice', // TODO: Make this dynamic based on route
          type: TransactionType.API_REQUEST,
          status:
            res.statusCode >= 200 && res.statusCode < 400
              ? TransactionStatus.COMPLETE
              : TransactionStatus.FAILED,
          endpoint: req.path,
          method: req.method,
          statusCode: res.statusCode,
          responseTime,
          requestSize: req.headers['content-length']
            ? parseInt(req.headers['content-length'] as string)
            : 0,
          responseSize: Buffer.byteLength(data, 'utf8'),
          clientIp: req.ip,
          userAgent: req.headers['user-agent'],
          timestamp: new Date(),
          metadata: {
            query: req.query,
            params: req.params,
          },
        };

        // Save asynchronously to avoid blocking response
        this.transactionLogModel.create(logData).catch((err) => {
          console.error('Failed to log usage:', err);
        });
      }

      return originalSend.call(this, data);
    };

    next();
  }
}
