import { Module } from '@nestjs/common';
import { CommonModule } from '@/common';
import { AuthModule } from '@/auth';
import { OrganizationController } from './organization.controller';

@Module({
  imports: [
    CommonModule, // Provides OrganizationService and schemas
    AuthModule, // Provides ApiKeyService
  ],
  controllers: [OrganizationController],
  providers: [],
  exports: [],
})
export class OrganizationModule {}
