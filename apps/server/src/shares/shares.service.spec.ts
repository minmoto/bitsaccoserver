import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { SharesService } from './shares.service';
import {
  SharesDocument,
  SharesOfferDocument,
  SharesTxStatus,
} from '../common/schemas';
import { MetricsService } from '../common';

describe('SharesService', () => {
  let service: SharesService;
  let _sharesModel: any;
  let _sharesOfferModel: any;
  let _metricsService: MetricsService;

  const mockExecutor = {
    exec: jest.fn(),
  };

  const mockSharesModel = {
    find: jest.fn(() => mockExecutor),
    findById: jest.fn(() => mockExecutor),
    findByIdAndUpdate: jest.fn(() => mockExecutor),
    findOne: jest.fn(() => mockExecutor),
    sort: jest.fn(() => mockExecutor),
  };

  const mockSharesOfferModel = {
    find: jest.fn(() => ({
      sort: jest.fn(() => mockExecutor),
    })),
    findById: jest.fn(() => mockExecutor),
    findByIdAndUpdate: jest.fn(() => mockExecutor),
  };

  const mockMetricsService = {
    recordSharesSubscriptionMetric: jest.fn(),
    recordSharesTransferMetric: jest.fn(),
    recordSharesOwnershipMetric: jest.fn(),
    recordMetric: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SharesService,
        {
          provide: getModelToken(SharesDocument.name),
          useValue: mockSharesModel,
        },
        {
          provide: getModelToken(SharesOfferDocument.name),
          useValue: mockSharesOfferModel,
        },
        {
          provide: MetricsService,
          useValue: mockMetricsService,
        },
      ],
    }).compile();

    service = module.get<SharesService>(SharesService);
    _sharesModel = module.get(getModelToken(SharesDocument.name));
    _sharesOfferModel = module.get(getModelToken(SharesOfferDocument.name));
    _metricsService = module.get<MetricsService>(MetricsService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('getSharesOffers', () => {
    it('should return shares offers', async () => {
      const mockOffers = [
        {
          _id: 'offer1',
          quantity: 1000,
          subscribedQuantity: 100,
          availableFrom: new Date('2024-01-01'),
          availableTo: new Date('2024-12-31'),
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];

      mockExecutor.exec.mockResolvedValue(mockOffers);

      const result = await service.getSharesOffers();

      expect(result).toHaveProperty('offers');
      expect(result).toHaveProperty('totalOfferQuantity');
      expect(result).toHaveProperty('totalSubscribedQuantity');
      expect(result.totalOfferQuantity).toBe(1000);
      expect(result.totalSubscribedQuantity).toBe(100);
    });
  });

  describe('offerShares', () => {
    it('should throw error for invalid quantity', async () => {
      const dto = { quantity: 0, availableFrom: '2024-01-01' };

      await expect(service.offerShares(dto)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('subscribeShares', () => {
    it('should throw error for non-existent offer', async () => {
      const dto = { userId: 'user123', offerId: 'offer456', quantity: 100 };

      mockExecutor.exec.mockResolvedValue(null);

      await expect(service.subscribeShares(dto)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw error for insufficient shares', async () => {
      const dto = { userId: 'user123', offerId: 'offer456', quantity: 100 };
      const mockOffer = {
        _id: 'offer456',
        quantity: 50,
        subscribedQuantity: 0,
      };

      mockExecutor.exec.mockResolvedValue(mockOffer);

      await expect(service.subscribeShares(dto)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('findSharesTransaction', () => {
    it('should return shares transaction', async () => {
      const mockShare = {
        _id: 'shares123',
        userId: 'user123',
        offerId: 'offer456',
        quantity: 100,
        status: SharesTxStatus.COMPLETE,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockExecutor.exec.mockResolvedValue(mockShare);

      const result = await service.findSharesTransaction({
        sharesId: 'shares123',
      });

      expect(result).toHaveProperty('id', 'shares123');
      expect(result).toHaveProperty('userId', 'user123');
      expect(result).toHaveProperty('status', SharesTxStatus.COMPLETE);
    });

    it('should throw error for non-existent transaction', async () => {
      mockExecutor.exec.mockResolvedValue(null);

      await expect(
        service.findSharesTransaction({ sharesId: 'shares123' }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('handleWalletTransactionUpdate', () => {
    it('should handle non-existent shares transaction', async () => {
      mockExecutor.exec.mockResolvedValue(null);

      await service.handleWalletTransactionUpdate('shares123', 'COMPLETE');

      expect(
        mockMetricsService.recordSharesSubscriptionMetric,
      ).not.toHaveBeenCalled();
    });
  });
});
