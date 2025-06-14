import * as africastalking from 'africastalking';
import { ConfigService } from '@nestjs/config';
import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { SendBulkSmsDto, SendSmsDto, MetricsService } from '@/common';

@Injectable()
export class SmsService {
  private readonly logger = new Logger(SmsService.name);
  private at: any;
  private smsconfig: { from: string; keyword: string } | null = null;
  private isConfigured = false;

  constructor(
    private readonly configService: ConfigService,
    private readonly metricsService: MetricsService,
  ) {
    this.logger.log('SmsService created');
    this.initializeSmsProvider();
  }

  private initializeSmsProvider() {
    try {
      const apiKey = this.configService.get<string>('SMS_AT_API_KEY');
      const username = this.configService.get<string>('SMS_AT_USERNAME');
      const from = this.configService.get<string>('SMS_AT_FROM');
      const keyword = this.configService.get<string>('SMS_AT_KEYWORD');

      if (!apiKey || !username || !from || !keyword) {
        this.logger.warn(
          'SMS configuration incomplete. SMS service will be disabled.',
        );
        this.isConfigured = false;
        return;
      }

      this.at = africastalking({
        apiKey,
        username,
      });

      this.smsconfig = {
        from,
        keyword,
      };

      this.isConfigured = true;
      this.logger.log('SMS service configured successfully');
    } catch (error) {
      this.logger.error('Failed to initialize SMS provider:', error);
      this.isConfigured = false;
    }
  }

  private checkConfiguration() {
    if (!this.isConfigured) {
      throw new BadRequestException(
        'SMS service provider not configured. Please check SMS_AT_* environment variables.',
      );
    }
  }

  async sendSms({ message, receiver }: SendSmsDto): Promise<void> {
    this.logger.log(`Sending sms to ${receiver} with message ${message}`);
    const startTime = Date.now();
    let _success = false;
    let errorType: string | undefined;

    try {
      this.checkConfiguration();

      const response = await this.at.SMS.send({
        ...this.smsconfig,
        to: receiver,
        message,
      });

      this.logger.log(`Sms sent with response ${JSON.stringify(response)}`);

      // Record successful SMS metric
      _success = true;
      this.metricsService.recordSmsMetric({
        receiver,
        messageLength: message.length,
        success: true,
        duration: Date.now() - startTime,
      });
    } catch (error) {
      errorType = error.message || 'Unknown error';
      this.logger.error(`Error sending SMS: ${errorType}`, error.stack);

      // Record failed SMS metric
      this.metricsService.recordSmsMetric({
        receiver,
        messageLength: message.length,
        success: false,
        duration: Date.now() - startTime,
        errorType,
      });

      throw error;
    }
  }

  async sendBulkSms({ message, receivers }: SendBulkSmsDto): Promise<void> {
    this.logger.log(
      `Sending bulk sms to ${receivers} with messages ${message}`,
    );
    const startTime = Date.now();
    let _success = false;
    let errorType: string | undefined;

    try {
      this.checkConfiguration();

      const response = await this.at.SMS.send({
        ...this.smsconfig,
        to: receivers,
        message,
      });

      this.logger.log(
        `Bulk sms sent with response ${JSON.stringify(response)}`,
      );

      // Record successful bulk SMS metric
      _success = true;
      this.metricsService.recordSmsBulkMetric({
        receiverCount: receivers.length,
        messageLength: message.length,
        success: true,
        duration: Date.now() - startTime,
      });
    } catch (error) {
      errorType = error.message || 'Unknown error';
      this.logger.error(`Error sending bulk SMS: ${errorType}`, error.stack);

      // Record failed bulk SMS metric
      this.metricsService.recordSmsBulkMetric({
        receiverCount: receivers.length,
        messageLength: message.length,
        success: false,
        duration: Date.now() - startTime,
        errorType,
      });

      throw error;
    }
  }

  /**
   * Check if SMS service is configured and available
   */
  isServiceAvailable(): boolean {
    return this.isConfigured;
  }

  /**
   * Get SMS service configuration status
   */
  getServiceStatus(): { configured: boolean; provider: string | null } {
    return {
      configured: this.isConfigured,
      provider: this.isConfigured ? 'AfricasTalking' : null,
    };
  }
}
