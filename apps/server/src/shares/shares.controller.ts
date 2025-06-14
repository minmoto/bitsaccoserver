import {
  ApiOperation,
  ApiBody,
  ApiBearerAuth,
  ApiCookieAuth,
  ApiTags,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import {
  Body,
  Controller,
  Logger,
  Post,
  Get,
  Put,
  Param,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  OfferSharesDto,
  SubscribeSharesDto,
  TransferSharesDto,
  UpdateSharesDto,
  PaginationDto,
  UnifiedAuthGuard,
} from '@/common';
import { SharesService } from './shares.service';

@ApiTags('shares')
@ApiBearerAuth()
@UseGuards(UnifiedAuthGuard)
@Controller('shares')
export class SharesController {
  private readonly logger = new Logger(SharesController.name);

  constructor(private readonly sharesService: SharesService) {
    this.logger.log('SharesController initialized');
  }

  @Post('offer')
  @ApiBearerAuth()
  @ApiCookieAuth()
  @ApiOperation({ summary: 'Create a new shares offer' })
  @ApiBody({ type: OfferSharesDto })
  async offerShares(@Body() req: OfferSharesDto) {
    return this.sharesService.offerShares(req);
  }

  @Get('offers')
  @ApiBearerAuth()
  @ApiCookieAuth()
  @ApiOperation({ summary: 'Get all shares offers' })
  async getSharesOffers() {
    return this.sharesService.getSharesOffers();
  }

  @Post('subscribe')
  @ApiBearerAuth()
  @ApiCookieAuth()
  @ApiOperation({ summary: 'Subscribe to shares' })
  @ApiBody({ type: SubscribeSharesDto })
  async subscribeShares(@Body() req: SubscribeSharesDto) {
    return this.sharesService.subscribeShares(req);
  }

  @Post('transfer')
  @ApiBearerAuth()
  @ApiCookieAuth()
  @ApiOperation({ summary: 'Transfer shares between users' })
  @ApiBody({ type: TransferSharesDto })
  async transferShares(@Body() req: TransferSharesDto) {
    return this.sharesService.transferShares(req);
  }

  @Put('update/:id')
  @ApiBearerAuth()
  @ApiCookieAuth()
  @ApiOperation({ summary: 'Update shares transaction' })
  @ApiParam({ name: 'id', description: 'Shares transaction ID' })
  @ApiBody({ type: UpdateSharesDto })
  async updateShares(@Param('id') sharesId: string, @Body() updates: any) {
    return this.sharesService.updateShares({ sharesId, updates });
  }

  @Get('user/:userId/transactions')
  @ApiBearerAuth()
  @ApiCookieAuth()
  @ApiOperation({ summary: 'Get user shares transactions' })
  @ApiParam({ name: 'userId', description: 'User ID' })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number',
  })
  @ApiQuery({
    name: 'size',
    required: false,
    type: Number,
    description: 'Page size',
  })
  async userSharesTransactions(
    @Param('userId') userId: string,
    @Query() pagination: PaginationDto,
  ) {
    return this.sharesService.userSharesTransactions({
      userId,
      pagination: {
        page: pagination.page || 1,
        size: pagination.size || 10,
      },
    });
  }

  @Get('transactions')
  @ApiBearerAuth()
  @ApiCookieAuth()
  @ApiOperation({ summary: 'Get all shares transactions' })
  async allSharesTransactions() {
    return this.sharesService.allSharesTransactions();
  }

  @Get('transaction/:id')
  @ApiBearerAuth()
  @ApiCookieAuth()
  @ApiOperation({ summary: 'Find specific shares transaction' })
  @ApiParam({ name: 'id', description: 'Shares transaction ID' })
  async findSharesTransaction(@Param('id') sharesId: string) {
    return this.sharesService.findSharesTransaction({ sharesId });
  }

  @Post('wallet-transaction-update')
  @ApiBearerAuth()
  @ApiCookieAuth()
  @ApiOperation({
    summary: 'Update shares transaction based on wallet transaction status',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        sharesTransactionId: {
          type: 'string',
          description: 'Shares transaction ID',
        },
        paymentStatus: {
          type: 'string',
          enum: ['COMPLETE', 'PROCESSING', 'FAILED', 'PENDING'],
          description: 'Payment status from wallet',
        },
        error: {
          type: 'string',
          description: 'Error message if payment failed',
        },
      },
      required: ['sharesTransactionId', 'paymentStatus'],
    },
  })
  async updateWalletTransaction(
    @Body()
    req: {
      sharesTransactionId: string;
      paymentStatus: 'COMPLETE' | 'PROCESSING' | 'FAILED' | 'PENDING';
      error?: string;
    },
  ) {
    await this.sharesService.handleWalletTransactionUpdate(
      req.sharesTransactionId,
      req.paymentStatus,
      req.error,
    );
    return { success: true, message: 'Wallet transaction status updated' };
  }
}
