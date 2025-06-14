import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { getModelToken } from '@nestjs/mongoose';
import { SmsController } from './sms.controller';
import { SmsService } from './sms.service';
import { ApiKeyDocument } from '@/common/schemas/api-key.schema';
import { OrganizationMember } from '@/common/schemas/organization.schema';
import { OrganizationServiceDocument } from '@/common/schemas/service.schema';

describe('SmsController', () => {
  let smsController: SmsController;
  let _smsService: SmsService;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [SmsController],
      providers: [
        {
          provide: SmsService,
          useValue: {
            sendSms: jest.fn(),
            sendBulkSms: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            decode: jest.fn(),
            sign: jest.fn(),
            verify: jest.fn(),
          },
        },
        {
          provide: getModelToken(ApiKeyDocument.name),
          useValue: {
            findOne: jest.fn(),
            find: jest.fn(),
            create: jest.fn(),
            findOneAndUpdate: jest.fn(),
          },
        },
        {
          provide: getModelToken(OrganizationMember.name),
          useValue: {
            findOne: jest.fn(),
            find: jest.fn(),
            create: jest.fn(),
            findOneAndUpdate: jest.fn(),
          },
        },
        {
          provide: getModelToken(OrganizationServiceDocument.name),
          useValue: {
            findOne: jest.fn(),
            find: jest.fn(),
            create: jest.fn(),
            findOneAndUpdate: jest.fn(),
          },
        },
      ],
    }).compile();

    smsController = app.get<SmsController>(SmsController);
    _smsService = app.get<SmsService>(SmsService);
  });

  it('should be defined', () => {
    expect(smsController).toBeDefined();
  });
});
