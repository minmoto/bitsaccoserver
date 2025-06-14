import {
  Controller,
  Get,
  Post,
  Put,
  Body,
  Param,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiParam } from '@nestjs/swagger';
import {
  CurrentUser,
  GlobalScope,
  RequiresApproval,
  SACCOAuthenticatedUser,
  Permission,
  PermissionScope,
  ServiceRole,
  GroupRole,
  SACCOAuthGuard,
  RequireRole,
  WorkflowType,
  ApprovalStatus,
  RiskLevel,
  ServiceContext,
} from '../common';
import {
  MakerCheckerService,
  WorkflowRequest,
  ApprovalRequest,
  SegregationService,
  OperationContext,
  ComplianceService,
  ComplianceMetrics,
  RiskManagementService,
  TransactionRisk,
  RiskAssessment,
  AuditService,
  AuditQueryFilters,
} from '.';

/**
 * Compliance Controller - Maker-Checker, Risk Management, and Regulatory Features
 */
@ApiTags('Compliance & Risk Management')
@Controller('compliance')
@UseGuards(SACCOAuthGuard)
export class ComplianceController {
  constructor(
    private makerCheckerService: MakerCheckerService,
    private segregationService: SegregationService,
    private complianceService: ComplianceService,
    private riskManagementService: RiskManagementService,
    private auditService: AuditService,
  ) {}

  // Maker-Checker Workflows

  @Post('workflows')
  @GlobalScope([Permission.FINANCE_DEPOSIT, Permission.FINANCE_WITHDRAW])
  @ApiOperation({ summary: 'Initiate approval workflow' })
  async initiateWorkflow(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Body()
    workflowData: {
      workflowType: WorkflowType;
      scope: PermissionScope;
      organizationId: string;
      chamaId?: string;
      operationData: {
        action: string;
        resourceType: string;
        resourceId?: string;
        parameters: Record<string, any>;
        estimatedValue?: number;
        currency?: string;
        description: string;
      };
      metadata?: {
        sourceSystem?: string;
        correlationId?: string;
        businessJustification?: string;
        urgency?: 'low' | 'medium' | 'high' | 'critical';
        customerImpact?: 'none' | 'low' | 'medium' | 'high';
      };
    },
  ) {
    const request: WorkflowRequest = {
      workflowType: workflowData.workflowType,
      scope: workflowData.scope,
      organizationId: workflowData.organizationId,
      chamaId: workflowData.chamaId,
      operationData: workflowData.operationData,
      metadata: workflowData.metadata,
    };

    return await this.makerCheckerService.initiateWorkflow(user, request);
  }

  @Get('workflows/pending')
  @GlobalScope([Permission.FINANCE_APPROVE])
  @ApiOperation({ summary: 'Get pending workflows for approval' })
  async getPendingWorkflows(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Query('scope') scope?: PermissionScope,
    @Query('workflowType') workflowType?: WorkflowType,
    @Query('limit') limit?: number,
    @Query('offset') offset?: number,
  ) {
    return await this.makerCheckerService.getPendingWorkflows(
      user,
      scope,
      workflowType,
      limit,
      offset,
    );
  }

  @Get('workflows/:workflowId')
  @GlobalScope([Permission.FINANCE_READ])
  @ApiOperation({ summary: 'Get workflow details' })
  @ApiParam({ name: 'workflowId', description: 'Workflow ID' })
  async getWorkflow(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Param('workflowId') workflowId: string,
  ) {
    return await this.makerCheckerService.getWorkflow(user, workflowId);
  }

  @Post('workflows/:workflowId/approve')
  @RequiresApproval()
  @GlobalScope([Permission.FINANCE_APPROVE])
  @ApiOperation({ summary: 'Approve or reject workflow' })
  @ApiParam({ name: 'workflowId', description: 'Workflow ID' })
  async submitApproval(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Param('workflowId') workflowId: string,
    @Body()
    approvalData: {
      status: 'approved' | 'rejected';
      comment?: string;
      ipAddress?: string;
      userAgent?: string;
    },
  ) {
    const request: ApprovalRequest = {
      workflowId,
      status:
        approvalData.status === 'approved'
          ? ApprovalStatus.APPROVED
          : ApprovalStatus.REJECTED,
      comment: approvalData.comment,
      ipAddress: approvalData.ipAddress,
      userAgent: approvalData.userAgent,
    };

    return await this.makerCheckerService.submitApproval(user, request);
  }

  @Post('workflows/:workflowId/cancel')
  @GlobalScope([Permission.FINANCE_WITHDRAW])
  @ApiOperation({ summary: 'Cancel pending workflow' })
  @ApiParam({ name: 'workflowId', description: 'Workflow ID' })
  async cancelWorkflow(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Param('workflowId') workflowId: string,
    @Body() cancellationData: { reason: string },
  ) {
    return await this.makerCheckerService.cancelWorkflow(
      user,
      workflowId,
      cancellationData.reason,
    );
  }

  // Segregation of Duties

  @Post('sod/check')
  @GlobalScope([Permission.SYSTEM_MONITOR])
  @ApiOperation({ summary: 'Check segregation of duties violations' })
  async checkSegregationViolation(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Body()
    operationData: {
      action: string;
      permissions: Permission[];
      roles: (ServiceRole | GroupRole)[];
      scope: PermissionScope;
      organizationId?: string;
      chamaId?: string;
      sessionId?: string;
      metadata?: Record<string, any>;
    },
  ) {
    const operationContext: Omit<OperationContext, 'timestamp'> = {
      userId: user.userId,
      action: operationData.action,
      permissions: operationData.permissions,
      roles: operationData.roles,
      scope: operationData.scope,
      organizationId: operationData.organizationId,
      chamaId: operationData.chamaId,
      sessionId: operationData.sessionId,
      metadata: operationData.metadata,
    };

    return await this.segregationService.checkSegregationViolation(
      user,
      operationContext,
    );
  }

  @Get('sod/rules')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.SYSTEM_CONFIG])
  @ApiOperation({ summary: 'Get segregation of duties rules (ADMIN+)' })
  async getSegregationRules(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Query('scope') scope?: PermissionScope,
    @Query('isActive') isActive?: boolean,
  ) {
    return await this.segregationService.getSegregationRules(
      user,
      scope,
      isActive,
    );
  }

  @Post('sod/rules')
  @RequireRole(ServiceRole.SYSTEM_ADMIN)
  @GlobalScope([Permission.SYSTEM_CONFIG])
  @ApiOperation({ summary: 'Create segregation rule (SYSTEM-ADMIN only)' })
  async createSegregationRule(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Body()
    ruleData: {
      ruleName: string;
      description: string;
      scope: PermissionScope;
      conflictingOperations: {
        operation1: {
          action: string;
          permissions: Permission[];
          roles: (ServiceRole | GroupRole)[];
        };
        operation2: {
          action: string;
          permissions: Permission[];
          roles: (ServiceRole | GroupRole)[];
        };
        conflictType:
          | 'same_user'
          | 'same_role'
          | 'same_session'
          | 'time_window';
        timeWindowHours?: number;
      };
      enforcement: {
        blockConflicting: boolean;
        requireApproval: boolean;
        alertLevel: 'info' | 'warning' | 'critical';
        notificationChannels: ('email' | 'sms' | 'dashboard' | 'audit')[];
      };
    },
  ) {
    return await this.segregationService.createSegregationRule(user, ruleData);
  }

  @Put('sod/rules/:ruleId/toggle')
  @RequireRole(ServiceRole.SYSTEM_ADMIN)
  @GlobalScope([Permission.SYSTEM_CONFIG])
  @ApiOperation({
    summary: 'Activate/deactivate segregation rule (SYSTEM-ADMIN only)',
  })
  @ApiParam({ name: 'ruleId', description: 'Rule ID' })
  async toggleSegregationRule(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Param('ruleId') ruleId: string,
    @Body() toggleData: { isActive: boolean },
  ) {
    return await this.segregationService.toggleSegregationRule(
      user,
      ruleId,
      toggleData.isActive,
    );
  }

  @Get('sod/violations/report')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.REPORTS_READ])
  @ApiOperation({ summary: 'Get segregation violations report (ADMIN+)' })
  async getViolationReport(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Query('startDate') startDate: string,
    @Query('endDate') endDate: string,
    @Query('scope') scope?: PermissionScope,
    @Query('organizationId') organizationId?: string,
    @Query('chamaId') chamaId?: string,
  ) {
    return await this.segregationService.getViolationReport(
      user,
      new Date(startDate),
      new Date(endDate),
      scope,
      organizationId,
      chamaId,
    );
  }

  // Risk Management

  @Post('risk/assess')
  @GlobalScope([Permission.FINANCE_READ])
  @ApiOperation({ summary: 'Assess transaction risk' })
  async assessTransactionRisk(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @ServiceContext() context: any,
    @Body()
    riskData: {
      amount: number;
      currency: string;
      transactionType: string;
      frequency: number;
      userRiskProfile: 'low' | 'medium' | 'high';
      counterpartyRisk?: 'low' | 'medium' | 'high';
      geographicRisk?: 'low' | 'medium' | 'high';
      timeOfDay: number;
      isWeekend: boolean;
      isHoliday?: boolean;
    },
  ): Promise<RiskAssessment> {
    const transactionRisk: TransactionRisk = {
      amount: riskData.amount,
      currency: riskData.currency,
      transactionType: riskData.transactionType,
      frequency: riskData.frequency,
      userRiskProfile: riskData.userRiskProfile,
      counterpartyRisk: riskData.counterpartyRisk,
      geographicRisk: riskData.geographicRisk,
      timeOfDay: riskData.timeOfDay,
      isWeekend: riskData.isWeekend,
      isHoliday: riskData.isHoliday,
    };

    return await this.riskManagementService.assessTransactionRisk(
      user,
      transactionRisk,
      context.scope,
      context.organizationId,
      context.chamaId,
    );
  }

  @Post('risk/limits/check')
  @GlobalScope([Permission.FINANCE_READ])
  @ApiOperation({ summary: 'Check transaction limits' })
  async checkTransactionLimits(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @ServiceContext() context: any,
    @Body()
    limitCheckData: {
      amount: number;
      currency: string;
      operationType: string;
    },
  ) {
    return await this.riskManagementService.checkTransactionLimits(
      user,
      limitCheckData.amount,
      limitCheckData.currency,
      limitCheckData.operationType,
      context.scope,
      context.organizationId,
      context.chamaId,
    );
  }

  @Get('risk/limits')
  @GlobalScope([Permission.FINANCE_READ])
  @ApiOperation({ summary: 'Get transaction limits' })
  async getTransactionLimits(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Query('scope') scope?: PermissionScope,
    @Query('organizationId') organizationId?: string,
    @Query('chamaId') chamaId?: string,
    @Query('isActive') isActive?: boolean,
  ) {
    return await this.riskManagementService.getTransactionLimits(
      user,
      scope,
      organizationId,
      chamaId,
      isActive,
    );
  }

  @Post('risk/limits')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.SYSTEM_CONFIG])
  @ApiOperation({ summary: 'Create transaction limit (ADMIN+)' })
  async createTransactionLimit(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Body()
    limitData: {
      limitName: string;
      scope: PermissionScope;
      organizationId?: string;
      chamaId?: string;
      userId?: string;
      applicableRoles: (ServiceRole | GroupRole)[];
      currency: string;
      limits: {
        maxTransactionAmount: number;
        minTransactionAmount?: number;
        dailyLimit?: number;
        weeklyLimit?: number;
        monthlyLimit?: number;
        yearlyLimit?: number;
        dailyTransactionCount?: number;
        monthlyTransactionCount?: number;
        totalLifetimeLimit?: number;
        outstandingLimit?: number;
      };
      applicableOperations: string[];
      overrideConditions: {
        allowOverride: boolean;
        overrideRoles: (ServiceRole | GroupRole)[];
        overridePermissions: Permission[];
        requiresApproval: boolean;
        maxOverridePercentage?: number;
      };
      effectiveFrom: Date;
      effectiveUntil?: Date;
    },
  ) {
    return await this.riskManagementService.createTransactionLimit(
      user,
      limitData,
    );
  }

  @Get('risk/report')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.REPORTS_READ])
  @ApiOperation({ summary: 'Generate risk report (ADMIN+)' })
  async generateRiskReport(
    @Query('scope') scope: PermissionScope,
    @Query('organizationId') organizationId?: string,
    @Query('chamaId') chamaId?: string,
    @Query('days') days?: number,
  ) {
    return await this.riskManagementService.generateRiskReport(
      scope,
      organizationId,
      chamaId,
      days,
    );
  }

  @Get('risk/monitor/realtime')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.SYSTEM_MONITOR])
  @ApiOperation({ summary: 'Monitor real-time risk patterns (ADMIN+)' })
  async monitorRealTimeRisk(
    @Query('scope') scope: PermissionScope,
    @Query('organizationId') organizationId?: string,
    @Query('chamaId') chamaId?: string,
  ) {
    return await this.riskManagementService.monitorRealTimeRisk(
      scope,
      organizationId,
      chamaId,
    );
  }

  // Compliance Monitoring

  @Get('events')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.REPORTS_READ])
  @ApiOperation({ summary: 'Get compliance events (ADMIN+)' })
  async getComplianceEvents(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Query('eventType') eventType?: string,
    @Query('severity') severity?: RiskLevel,
    @Query('scope') scope?: PermissionScope,
    @Query('organizationId') organizationId?: string,
    @Query('chamaId') chamaId?: string,
    @Query('status')
    status?: 'open' | 'investigating' | 'resolved' | 'false_positive',
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('limit') limit?: number,
    @Query('offset') offset?: number,
  ) {
    const filters = {
      eventType,
      severity,
      scope,
      organizationId,
      chamaId,
      status,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      limit,
      offset,
    };

    return await this.complianceService.getComplianceEvents(user, filters);
  }

  @Put('events/:eventId')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.SYSTEM_CONFIG])
  @ApiOperation({ summary: 'Update compliance event status (ADMIN+)' })
  @ApiParam({ name: 'eventId', description: 'Event ID' })
  async updateEventStatus(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Param('eventId') eventId: string,
    @Body()
    updateData: {
      status: 'open' | 'investigating' | 'resolved' | 'false_positive';
      assignedTo?: string;
      resolutionNotes?: string;
      escalate?: boolean;
      escalatedTo?: string;
    },
  ) {
    return await this.complianceService.updateEventStatus(
      user,
      eventId,
      updateData,
    );
  }

  @Get('metrics')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.REPORTS_READ])
  @ApiOperation({ summary: 'Get compliance metrics dashboard (ADMIN+)' })
  async getComplianceMetrics(
    @Query('scope') scope: PermissionScope,
    @Query('organizationId') organizationId?: string,
    @Query('chamaId') chamaId?: string,
    @Query('timeRange') timeRange?: '24h' | '7d' | '30d' | '90d',
  ): Promise<ComplianceMetrics> {
    return await this.complianceService.getComplianceMetrics(
      scope,
      organizationId,
      chamaId,
      timeRange,
    );
  }

  @Get('health')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.SYSTEM_MONITOR])
  @ApiOperation({ summary: 'Run compliance health check (ADMIN+)' })
  async runComplianceHealthCheck(
    @Query('scope') scope: PermissionScope,
    @Query('organizationId') organizationId?: string,
    @Query('chamaId') chamaId?: string,
  ) {
    return await this.complianceService.runComplianceHealthCheck(
      scope,
      organizationId,
      chamaId,
    );
  }

  // Regulatory Reporting

  @Post('reports/generate')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.REPORTS_EXPORT])
  @ApiOperation({ summary: 'Generate regulatory report (ADMIN+)' })
  async generateRegulatoryReport(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Body()
    reportData: {
      reportType: string;
      regulator: string;
      reportingPeriod: {
        startDate: Date;
        endDate: Date;
        frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'annually';
      };
      scope: PermissionScope;
      organizationId?: string;
    },
  ) {
    return await this.complianceService.generateRegulatoryReport(
      user,
      reportData.reportType,
      reportData.regulator,
      reportData.reportingPeriod,
      reportData.scope,
      reportData.organizationId,
    );
  }

  @Get('reports')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.REPORTS_READ])
  @ApiOperation({ summary: 'Get regulatory reports (ADMIN+)' })
  async getRegulatoryReports(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Query('reportType') reportType?: string,
    @Query('regulator') regulator?: string,
    @Query('status') status?: string,
    @Query('scope') scope?: PermissionScope,
    @Query('organizationId') organizationId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('limit') limit?: number,
    @Query('offset') offset?: number,
  ) {
    const filters = {
      reportType,
      regulator,
      status,
      scope,
      organizationId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      limit,
      offset,
    };

    return await this.complianceService.getRegulatoryReports(user, filters);
  }

  @Post('reports/:reportId/submit')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.REPORTS_EXPORT])
  @ApiOperation({ summary: 'Submit regulatory report (ADMIN+)' })
  @ApiParam({ name: 'reportId', description: 'Report ID' })
  async submitRegulatoryReport(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Param('reportId') reportId: string,
  ) {
    return await this.complianceService.submitRegulatoryReport(user, reportId);
  }

  // Audit Logs

  @Get('audit')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.REPORTS_READ])
  @ApiOperation({ summary: 'Get audit logs (ADMIN+)' })
  async getAuditLogs(
    @Query('userId') userId?: string,
    @Query('action') action?: string,
    @Query('resourceType') resourceType?: string,
    @Query('scope') scope?: PermissionScope,
    @Query('organizationId') organizationId?: string,
    @Query('chamaId') chamaId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('sensitiveData') sensitiveData?: boolean,
    @Query('riskLevel') riskLevel?: string,
    @Query('limit') limit?: number,
    @Query('offset') offset?: number,
  ) {
    const filters: AuditQueryFilters = {
      userId,
      action,
      resourceType,
      scope,
      organizationId,
      chamaId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      sensitiveData,
      riskLevel,
      limit,
      offset,
    };

    return await this.auditService.getAuditLogs(filters);
  }

  @Get('audit/search')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.REPORTS_READ])
  @ApiOperation({
    summary: 'Search audit logs with advanced criteria (ADMIN+)',
  })
  async searchAuditLogs(
    @Query('keyword') keyword?: string,
    @Query('userId') userId?: string,
    @Query('ipAddress') ipAddress?: string,
    @Query('userAgent') userAgent?: string,
    @Query('minAmount') minAmount?: number,
    @Query('maxAmount') maxAmount?: number,
    @Query('riskLevels') riskLevels?: string,
    @Query('dataClassifications') dataClassifications?: string,
    @Query('scope') scope?: PermissionScope,
    @Query('organizationId') organizationId?: string,
    @Query('chamaId') chamaId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('limit') limit?: number,
    @Query('offset') offset?: number,
  ) {
    const searchCriteria = {
      keyword,
      userId,
      ipAddress,
      userAgent,
      amountRange:
        minAmount && maxAmount ? { min: minAmount, max: maxAmount } : undefined,
      riskLevels: riskLevels ? riskLevels.split(',') : undefined,
      dataClassifications: dataClassifications
        ? dataClassifications.split(',')
        : undefined,
      scope,
      organizationId,
      chamaId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      limit,
      offset,
    };

    return await this.auditService.searchAuditLogs(searchCriteria);
  }

  @Get('audit/statistics')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.REPORTS_READ])
  @ApiOperation({ summary: 'Get audit statistics and analytics (ADMIN+)' })
  async getAuditStatistics(
    @Query('scope') scope?: PermissionScope,
    @Query('organizationId') organizationId?: string,
    @Query('chamaId') chamaId?: string,
    @Query('days') days?: number,
  ) {
    return await this.auditService.getAuditStatistics(
      scope,
      organizationId,
      chamaId,
      days,
    );
  }

  @Post('audit/export')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.REPORTS_EXPORT])
  @ApiOperation({
    summary: 'Export audit logs for compliance reporting (ADMIN+)',
  })
  async exportAuditLogs(
    @Body()
    exportRequest: {
      filters: AuditQueryFilters;
      format: 'json' | 'csv' | 'pdf';
    },
  ) {
    return await this.auditService.exportAuditLogs(
      exportRequest.filters,
      exportRequest.format,
    );
  }

  @Get('audit/compliance-report')
  @RequireRole(ServiceRole.ADMIN)
  @GlobalScope([Permission.REPORTS_EXPORT])
  @ApiOperation({ summary: 'Get compliance-ready audit report (ADMIN+)' })
  async getComplianceAuditReport(
    @CurrentUser() user: SACCOAuthenticatedUser,
    @Query('scope') scope: PermissionScope,
    @Query('organizationId') organizationId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
  ) {
    return await this.auditService.getComplianceAuditReport(
      scope,
      organizationId,
      startDate ? new Date(startDate) : undefined,
      endDate ? new Date(endDate) : undefined,
    );
  }
}
