import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  UseGuards,
  Request,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
} from '@nestjs/swagger';
import {
  AddMemberDto,
  ApiKeyService,
  AuthenticatedRequest,
  CreateApiKeyDto,
  CreateOrganizationDto,
  OrganizationService,
  RBACGuard,
  Roles,
  UnifiedAuthGuard,
  UpdateOrganizationDto,
  UserRole,
} from '@/common';

@ApiTags('orgs')
@ApiBearerAuth()
@UseGuards(UnifiedAuthGuard)
@Controller('organizations')
export class OrganizationController {
  constructor(
    private readonly organizationService: OrganizationService,
    private readonly apiKeyService: ApiKeyService,
  ) {}

  @Post()
  @ApiOperation({ summary: 'Create a new organization' })
  @ApiResponse({
    status: 201,
    description: 'Organization created successfully',
  })
  async create(
    @Body() createOrganizationDto: CreateOrganizationDto,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.organizationService.create(
      createOrganizationDto,
      req.user.sub,
      req.user.email,
    );
  }

  @Get()
  @ApiOperation({ summary: 'Get all organizations for current user' })
  @ApiResponse({
    status: 200,
    description: 'Organizations retrieved successfully',
  })
  async findAll(@Request() req: AuthenticatedRequest) {
    return this.organizationService.findAll(req.user.sub);
  }

  @Get(':id')
  @UseGuards(RBACGuard)
  @Roles(UserRole.DEVELOPER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Get organization by ID' })
  @ApiResponse({
    status: 200,
    description: 'Organization retrieved successfully',
  })
  async findOne(@Param('id') id: string) {
    return this.organizationService.findOne(id);
  }

  @Patch(':id')
  @UseGuards(RBACGuard)
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Update organization' })
  @ApiResponse({
    status: 200,
    description: 'Organization updated successfully',
  })
  async update(
    @Param('id') id: string,
    @Body() updateOrganizationDto: UpdateOrganizationDto,
  ) {
    return this.organizationService.update(id, updateOrganizationDto);
  }

  @Delete(':id')
  @UseGuards(RBACGuard)
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Delete organization' })
  @ApiResponse({
    status: 200,
    description: 'Organization deleted successfully',
  })
  async remove(@Param('id') id: string) {
    return this.organizationService.delete(id);
  }

  @Get(':id/members')
  @UseGuards(RBACGuard)
  @Roles(UserRole.DEVELOPER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Get organization members' })
  @ApiResponse({ status: 200, description: 'Members retrieved successfully' })
  async getMembers(@Param('id') id: string) {
    return this.organizationService.getMembers(id);
  }

  @Post(':id/members')
  @UseGuards(RBACGuard)
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Add member to organization' })
  @ApiBody({
    type: AddMemberDto,
    description: 'Member details to add to the organization',
    examples: {
      developer: {
        summary: 'Add developer member',
        description: 'Example of adding a developer to the organization',
        value: {
          userId: 'user-123-abc',
          role: 'developer',
        },
      },
      admin: {
        summary: 'Add admin member',
        description: 'Example of adding an admin to the organization',
        value: {
          userId: 'user-456-def',
          role: 'admin',
        },
      },
    },
  })
  @ApiResponse({
    status: 201,
    description: 'Member added successfully',
    schema: {
      type: 'object',
      properties: {
        userId: { type: 'string' },
        organizationId: { type: 'string' },
        role: { type: 'string', enum: Object.values(UserRole) },
        invitedBy: { type: 'string' },
        invitedAt: { type: 'string', format: 'date-time' },
        joinedAt: { type: 'string', format: 'date-time' },
        isActive: { type: 'boolean' },
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Invalid request data' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions' })
  @ApiResponse({ status: 409, description: 'User is already a member' })
  async addMember(
    @Param('id') organizationId: string,
    @Body() addMemberDto: AddMemberDto,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.organizationService.addMember(
      organizationId,
      addMemberDto.userId,
      addMemberDto.role,
      req.user.sub,
    );
  }

  // API Key Management Endpoints
  @Post(':id/api-keys')
  @UseGuards(RBACGuard)
  @Roles(UserRole.DEVELOPER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Create a new API key for organization' })
  @ApiResponse({ status: 201, description: 'API key created successfully' })
  async createApiKey(
    @Param('id') organizationId: string,
    @Body() createApiKeyDto: CreateApiKeyDto,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.apiKeyService.create(
      organizationId,
      req.user.sub,
      createApiKeyDto,
    );
  }

  @Get(':id/api-keys')
  @UseGuards(RBACGuard)
  @Roles(UserRole.DEVELOPER, UserRole.ADMIN)
  @ApiOperation({ summary: 'List organization API keys' })
  @ApiResponse({ status: 200, description: 'API keys retrieved successfully' })
  async getApiKeys(@Param('id') organizationId: string) {
    return this.apiKeyService.findAll(organizationId);
  }

  @Get(':id/api-keys/:keyId')
  @UseGuards(RBACGuard)
  @Roles(UserRole.DEVELOPER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Get API key details' })
  @ApiResponse({ status: 200, description: 'API key retrieved successfully' })
  async getApiKey(
    @Param('id') organizationId: string,
    @Param('keyId') keyId: string,
  ) {
    return this.apiKeyService.findOne(organizationId, keyId);
  }

  @Delete(':id/api-keys/:keyId')
  @UseGuards(RBACGuard)
  @Roles(UserRole.DEVELOPER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Delete/revoke API key' })
  @ApiResponse({ status: 200, description: 'API key revoked successfully' })
  async deleteApiKey(
    @Param('id') organizationId: string,
    @Param('keyId') keyId: string,
  ) {
    return this.apiKeyService.remove(organizationId, keyId);
  }

  @Get(':id/api-keys/:keyId/usage')
  @UseGuards(RBACGuard)
  @Roles(UserRole.DEVELOPER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Get API key usage statistics' })
  @ApiResponse({
    status: 200,
    description: 'Usage statistics retrieved successfully',
  })
  async getApiKeyUsage(
    @Param('id') organizationId: string,
    @Param('keyId') keyId: string,
  ) {
    return this.apiKeyService.getUsage(organizationId, keyId);
  }

  // Services, Usage & Billing Endpoints (moved from ManagerController)
  @Get(':id/services')
  @UseGuards(RBACGuard)
  @Roles(UserRole.DEVELOPER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Get available services for organization' })
  @ApiResponse({ status: 200, description: 'Services retrieved successfully' })
  async getOrganizationServices(@Param('id') organizationId: string) {
    // TODO: Implement service listing based on organization
    return {
      organizationId,
      services: [],
    };
  }

  @Get(':id/usage')
  @UseGuards(RBACGuard)
  @Roles(UserRole.DEVELOPER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Get organization usage statistics' })
  @ApiResponse({
    status: 200,
    description: 'Usage statistics retrieved successfully',
  })
  async getUsageStats(
    @Param('id') organizationId: string,
    @Query('period') period: string = 'current_month',
    @Query('service') service?: string,
    @Query('apiKeyId') apiKeyId?: string,
  ) {
    // TODO: Implement usage statistics
    return {
      organizationId,
      period,
      service,
      apiKeyId,
      statistics: {
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        totalCost: 0,
        averageResponseTime: 0,
      },
    };
  }

  @Get(':id/billing')
  @UseGuards(RBACGuard)
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Get organization billing information' })
  @ApiResponse({
    status: 200,
    description: 'Billing information retrieved successfully',
  })
  async getBillingInfo(@Param('id') organizationId: string) {
    // TODO: Implement billing information
    return {
      organizationId,
      billing: {
        currentBalance: 0,
        currency: 'USD',
        monthlySpend: 0,
        lastPayment: null,
        nextBillingDate: null,
      },
    };
  }
}
