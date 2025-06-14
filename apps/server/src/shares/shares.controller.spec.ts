import { Test, TestingModule } from '@nestjs/testing';
import { SharesController } from './shares.controller';
import { SharesService } from './shares.service';
import { UnifiedAuthGuard } from '@/common';

describe('SharesController', () => {
  let controller: SharesController;
  let service: SharesService;

  const mockSharesService = {
    offerShares: jest.fn(),
    getSharesOffers: jest.fn(),
    subscribeShares: jest.fn(),
    transferShares: jest.fn(),
    updateShares: jest.fn(),
    userSharesTransactions: jest.fn(),
    allSharesTransactions: jest.fn(),
    findSharesTransaction: jest.fn(),
    handleWalletTransactionUpdate: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [SharesController],
      providers: [
        {
          provide: SharesService,
          useValue: mockSharesService,
        },
      ],
    })
      .overrideGuard(UnifiedAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<SharesController>(SharesController);
    service = module.get<SharesService>(SharesService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('offerShares', () => {
    it('should call service.offerShares', async () => {
      const dto = {
        quantity: 1000,
        availableFrom: '2024-01-01',
        availableTo: '2024-12-31',
      };
      const expectedResult = {
        offers: [],
        totalOfferQuantity: 1000,
        totalSubscribedQuantity: 0,
      };

      mockSharesService.offerShares.mockResolvedValue(expectedResult);

      const result = await controller.offerShares(dto);

      expect(service.offerShares).toHaveBeenCalledWith(dto);
      expect(result).toEqual(expectedResult);
    });
  });

  describe('getSharesOffers', () => {
    it('should call service.getSharesOffers', async () => {
      const expectedResult = {
        offers: [],
        totalOfferQuantity: 0,
        totalSubscribedQuantity: 0,
      };

      mockSharesService.getSharesOffers.mockResolvedValue(expectedResult);

      const result = await controller.getSharesOffers();

      expect(service.getSharesOffers).toHaveBeenCalled();
      expect(result).toEqual(expectedResult);
    });
  });

  describe('subscribeShares', () => {
    it('should call service.subscribeShares', async () => {
      const dto = { userId: 'user123', offerId: 'offer456', quantity: 100 };
      const expectedResult = {
        userId: 'user123',
        shareHoldings: 100,
        shares: { transactions: [], page: 1, size: 10, pages: 1 },
        offers: {
          offers: [],
          totalOfferQuantity: 1000,
          totalSubscribedQuantity: 100,
        },
      };

      mockSharesService.subscribeShares.mockResolvedValue(expectedResult);

      const result = await controller.subscribeShares(dto);

      expect(service.subscribeShares).toHaveBeenCalledWith(dto);
      expect(result).toEqual(expectedResult);
    });
  });

  describe('findSharesTransaction', () => {
    it('should call service.findSharesTransaction', async () => {
      const sharesId = 'shares123';
      const expectedResult = {
        id: 'shares123',
        userId: 'user123',
        offerId: 'offer456',
        quantity: 100,
        status: 4,
        createdAt: '2024-01-01T00:00:00.000Z',
        updatedAt: '2024-01-01T00:00:00.000Z',
      };

      mockSharesService.findSharesTransaction.mockResolvedValue(expectedResult);

      const result = await controller.findSharesTransaction(sharesId);

      expect(service.findSharesTransaction).toHaveBeenCalledWith({ sharesId });
      expect(result).toEqual(expectedResult);
    });
  });

  describe('updateWalletTransaction', () => {
    it('should call service.handleWalletTransactionUpdate', async () => {
      const req = {
        sharesTransactionId: 'shares123',
        paymentStatus: 'COMPLETE' as const,
      };

      mockSharesService.handleWalletTransactionUpdate.mockResolvedValue(
        undefined,
      );

      const result = await controller.updateWalletTransaction(req);

      expect(service.handleWalletTransactionUpdate).toHaveBeenCalledWith(
        req.sharesTransactionId,
        req.paymentStatus,
        undefined,
      );
      expect(result).toEqual({
        success: true,
        message: 'Wallet transaction status updated',
      });
    });

    it('should call service.handleWalletTransactionUpdate with error', async () => {
      const req = {
        sharesTransactionId: 'shares123',
        paymentStatus: 'FAILED' as const,
        error: 'Payment failed',
      };

      mockSharesService.handleWalletTransactionUpdate.mockResolvedValue(
        undefined,
      );

      const result = await controller.updateWalletTransaction(req);

      expect(service.handleWalletTransactionUpdate).toHaveBeenCalledWith(
        req.sharesTransactionId,
        req.paymentStatus,
        req.error,
      );
      expect(result).toEqual({
        success: true,
        message: 'Wallet transaction status updated',
      });
    });
  });
});
