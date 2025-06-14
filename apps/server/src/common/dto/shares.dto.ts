import { ApiProperty } from '@nestjs/swagger';
import {
  IsNotEmpty,
  IsNumber,
  IsString,
  IsOptional,
  IsDateString,
  Min,
} from 'class-validator';
import { SharesTxStatus } from '../schemas';

export class OfferSharesDto {
  @ApiProperty({ description: 'Number of shares to offer', example: 1000 })
  @IsNotEmpty()
  @IsNumber()
  @Min(1)
  quantity: number;

  @ApiProperty({
    description: 'Date when shares become available',
    example: '2024-01-01',
  })
  @IsNotEmpty()
  @IsDateString()
  availableFrom: string;

  @ApiProperty({
    description: 'Date when shares expire (optional)',
    example: '2024-12-31',
    required: false,
  })
  @IsOptional()
  @IsDateString()
  availableTo?: string;
}

export class SubscribeSharesDto {
  @ApiProperty({
    description: 'User ID subscribing to shares',
    example: 'user123',
  })
  @IsNotEmpty()
  @IsString()
  userId: string;

  @ApiProperty({ description: 'Share offer ID', example: 'offer456' })
  @IsNotEmpty()
  @IsString()
  offerId: string;

  @ApiProperty({ description: 'Number of shares to subscribe', example: 100 })
  @IsNotEmpty()
  @IsNumber()
  @Min(1)
  quantity: number;
}

export class TransferSharesDto {
  @ApiProperty({
    description: 'Shares transaction ID to transfer from',
    example: 'shares789',
  })
  @IsNotEmpty()
  @IsString()
  sharesId: string;

  @ApiProperty({
    description: 'User ID transferring shares',
    example: 'user123',
  })
  @IsNotEmpty()
  @IsString()
  fromUserId: string;

  @ApiProperty({ description: 'User ID receiving shares', example: 'user456' })
  @IsNotEmpty()
  @IsString()
  toUserId: string;

  @ApiProperty({ description: 'Number of shares to transfer', example: 50 })
  @IsNotEmpty()
  @IsNumber()
  @Min(1)
  quantity: number;

  @ApiProperty({
    description: 'Reason for transfer (optional)',
    example: 'Gift to family member',
    required: false,
  })
  @IsOptional()
  @IsString()
  reason?: string;
}

export class UpdateSharesDto {
  @ApiProperty({
    description: 'Shares transaction ID to update',
    example: 'shares789',
  })
  @IsNotEmpty()
  @IsString()
  sharesId: string;

  @ApiProperty({ description: 'Updates to apply' })
  updates: {
    quantity?: number;
    status?: SharesTxStatus;
    transfer?: {
      fromUserId: string;
      toUserId: string;
      quantity: number;
      reason?: string;
    };
    offerId?: string;
  };
}

export class UserSharesDto {
  @ApiProperty({ description: 'User ID to get shares for', example: 'user123' })
  @IsNotEmpty()
  @IsString()
  userId: string;

  @ApiProperty({ description: 'Pagination parameters', required: false })
  @IsOptional()
  pagination?: {
    page: number;
    size: number;
  };
}

export class FindSharesTxDto {
  @ApiProperty({
    description: 'Shares transaction ID to find',
    example: 'shares789',
  })
  @IsNotEmpty()
  @IsString()
  sharesId: string;
}

export class PaginationDto {
  @ApiProperty({ description: 'Page number', example: 1, default: 1 })
  @IsOptional()
  @IsNumber()
  @Min(1)
  page?: number = 1;

  @ApiProperty({ description: 'Page size', example: 10, default: 10 })
  @IsOptional()
  @IsNumber()
  @Min(1)
  size?: number = 10;
}
