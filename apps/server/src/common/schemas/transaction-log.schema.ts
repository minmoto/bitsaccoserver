import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

export enum TransactionType {
  API_REQUEST = 'api_request',
  SMS = 'sms',
  AUTH = 'auth',
  BILLING_CHARGE = 'billing_charge',
  BILLING_CREDIT = 'billing_credit',
  LIMIT_EXCEEDED = 'limit_exceeded',
}

export enum TransactionStatus {
  PENDING = 0,
  PROCESSING = 1,
  FAILED = 2,
  COMPLETE = 3,
  UNRECOGNIZED = -1,
}

@Schema({ timestamps: true })
export class TransactionLogDocument {
  @Prop({ required: true })
  organizationId: string;

  @Prop()
  apiKeyId?: string;

  @Prop({ required: true })
  serviceId: string;

  @Prop({ type: String, enum: TransactionType, required: true })
  type: TransactionType;

  @Prop({ type: String, enum: TransactionStatus, required: true })
  status: TransactionStatus;

  @Prop({ required: true })
  endpoint: string;

  @Prop()
  method?: string;

  @Prop()
  statusCode?: number;

  @Prop()
  responseTime?: number;

  @Prop()
  requestSize?: number;

  @Prop()
  responseSize?: number;

  @Prop()
  cost?: number;

  @Prop()
  currency?: string;

  @Prop()
  volume?: number;

  @Prop()
  clientIp?: string;

  @Prop()
  userAgent?: string;

  @Prop()
  errorMessage?: string;

  @Prop({ type: Object })
  metadata?: Record<string, any>;

  @Prop({ index: true })
  timestamp: Date;
}

@Schema({ timestamps: true })
export class UsageAggregation {
  @Prop({ required: true })
  organizationId: string;

  @Prop()
  apiKeyId?: string;

  @Prop({ required: true })
  serviceId: string;

  @Prop({ required: true })
  period: string; // YYYY-MM-DD for daily, YYYY-MM for monthly

  @Prop({ type: String, enum: ['daily', 'monthly'], required: true })
  granularity: 'daily' | 'monthly';

  @Prop({ default: 0 })
  totalRequests: number;

  @Prop({ default: 0 })
  successfulRequests: number;

  @Prop({ default: 0 })
  failedRequests: number;

  @Prop({ default: 0 })
  totalCost: number;

  @Prop({ default: 0 })
  totalVolume: number;

  @Prop({ default: 0 })
  averageResponseTime: number;
}

export const TransactionLogSchema = SchemaFactory.createForClass(
  TransactionLogDocument,
);
export const UsageAggregationSchema =
  SchemaFactory.createForClass(UsageAggregation);

// Add indexes for better query performance
TransactionLogSchema.index({ organizationId: 1, timestamp: -1 });
TransactionLogSchema.index({ apiKeyId: 1, timestamp: -1 });
TransactionLogSchema.index({ serviceId: 1, timestamp: -1 });
UsageAggregationSchema.index({ organizationId: 1, serviceId: 1, period: -1 });
