import {
  Injectable,
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { EventEmitter2 } from '@nestjs/event-emitter';
import {
  ApprovalWorkflow,
  ApprovalWorkflowDocument,
  ApprovalStatus,
  WorkflowType,
  RiskLevel,
  SegregationRule,
  SegregationRuleDocument,
  TransactionLimit,
  TransactionLimitDocument,
  SACCOAuthenticatedUser,
  Permission,
  PermissionScope,
  ServiceRole,
  GroupRole,
} from '../common';
import { PermissionService } from './permission.service';
import { ComplianceService } from './compliance.service';

export interface WorkflowRequest {
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
}

export interface ApprovalRequest {
  workflowId: string;
  status: ApprovalStatus.APPROVED | ApprovalStatus.REJECTED;
  comment?: string;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Maker-Checker Service
 * Implements dual control mechanisms and approval workflows
 */
@Injectable()
export class MakerCheckerService {
  constructor(
    @InjectModel(ApprovalWorkflow.name)
    private workflowModel: Model<ApprovalWorkflowDocument>,
    @InjectModel(SegregationRule.name)
    private segregationRuleModel: Model<SegregationRuleDocument>,
    @InjectModel(TransactionLimit.name)
    private transactionLimitModel: Model<TransactionLimitDocument>,
    private permissionService: PermissionService,
    private complianceService: ComplianceService,
    private eventEmitter: EventEmitter2,
  ) {}

  /**
   * Initiate a new approval workflow
   */
  async initiateWorkflow(
    user: SACCOAuthenticatedUser,
    request: WorkflowRequest,
  ): Promise<ApprovalWorkflowDocument> {
    // Check if user can initiate this type of workflow
    await this.validateInitiatorPermissions(user, request);

    // Check segregation of duties
    await this.checkSegregationRules(user, request);

    // Check transaction limits
    await this.checkTransactionLimits(user, request);

    // Determine risk level and approval requirements
    const riskLevel = await this.assessRiskLevel(request);
    const approvalChain = await this.buildApprovalChain(request, riskLevel);

    // Run compliance checks
    const complianceChecks = await this.runComplianceChecks(request);

    // Create workflow
    const workflow = new this.workflowModel({
      workflowType: request.workflowType,
      initiatedBy: user.userId,
      organizationId: request.organizationId,
      chamaId: request.chamaId,
      scope: request.scope,
      riskLevel,
      operationData: request.operationData,
      approvalChain,
      complianceChecks,
      approvals: [],
      expiresAt: new Date(
        Date.now() + approvalChain.timeoutHours * 60 * 60 * 1000,
      ),
      metadata: request.metadata || {},
      tags: this.generateWorkflowTags(request),
    });

    const savedWorkflow = await workflow.save();

    // Emit workflow initiated event
    this.eventEmitter.emit('workflow.initiated', {
      workflowId: savedWorkflow._id,
      initiator: user.userId,
      workflowType: request.workflowType,
      riskLevel,
    });

    // Send notifications to potential approvers
    await this.notifyApprovers(savedWorkflow);

    return savedWorkflow;
  }

  /**
   * Submit approval or rejection
   */
  async submitApproval(
    user: SACCOAuthenticatedUser,
    request: ApprovalRequest,
  ): Promise<ApprovalWorkflowDocument> {
    const workflow = await this.workflowModel.findById(request.workflowId);
    if (!workflow) {
      throw new NotFoundException('Workflow not found');
    }

    // Validate approver permissions
    await this.validateApproverPermissions(user, workflow);

    // Check if workflow has expired
    if (workflow.expiresAt && workflow.expiresAt < new Date()) {
      workflow.status = ApprovalStatus.EXPIRED;
      await workflow.save();
      throw new BadRequestException('Workflow has expired');
    }

    // Check if already approved/rejected by this user
    const existingApproval = workflow.approvals.find(
      (approval) => approval.approverId === user.userId,
    );
    if (existingApproval) {
      throw new BadRequestException(
        'User has already provided approval for this workflow',
      );
    }

    // Check self-approval rules
    if (
      workflow.initiatedBy === user.userId &&
      !workflow.approvalChain.allowSelfApproval
    ) {
      throw new ForbiddenException(
        'Self-approval not allowed for this workflow',
      );
    }

    // Add approval
    workflow.approvals.push({
      approverId: user.userId,
      approverRole: this.getUserHighestRole(user, workflow.scope),
      status: request.status,
      comment: request.comment,
      approvedAt: new Date(),
      ipAddress: request.ipAddress,
      userAgent: request.userAgent,
    });

    // Check if workflow is complete
    const workflowComplete = await this.checkWorkflowCompletion(workflow);

    if (workflowComplete) {
      if (request.status === ApprovalStatus.REJECTED) {
        workflow.status = ApprovalStatus.REJECTED;
      } else {
        workflow.status = ApprovalStatus.APPROVED;
        // Execute the operation if fully approved
        await this.executeApprovedOperation(workflow);
      }
    }

    const savedWorkflow = await workflow.save();

    // Emit approval event
    this.eventEmitter.emit('workflow.approval_submitted', {
      workflowId: savedWorkflow._id,
      approver: user.userId,
      status: request.status,
      complete: workflowComplete,
    });

    return savedWorkflow;
  }

  /**
   * Get pending workflows for a user
   */
  async getPendingWorkflows(
    user: SACCOAuthenticatedUser,
    scope?: PermissionScope,
    workflowType?: WorkflowType,
    limit: number = 50,
    offset: number = 0,
  ): Promise<{
    workflows: ApprovalWorkflowDocument[];
    total: number;
  }> {
    const query: any = {
      status: ApprovalStatus.PENDING,
      expiresAt: { $gt: new Date() },
      'approvals.approverId': { $ne: user.userId }, // Exclude already approved by user
    };

    // Filter by scope access
    if (scope) {
      query.scope = scope;
    }

    if (workflowType) {
      query.workflowType = workflowType;
    }

    // Filter by user's permissions and access
    const accessibleOrgs =
      user.groupMemberships
        ?.filter((m) => m.groupType === 'organization')
        .map((m) => m.groupId) || [];

    const accessibleChamas =
      user.groupMemberships
        ?.filter((m) => m.groupType === 'chama')
        .map((m) => m.groupId) || [];

    if (user.serviceRole !== ServiceRole.SYSTEM_ADMIN) {
      query.$or = [
        { organizationId: { $in: accessibleOrgs } },
        { chamaId: { $in: accessibleChamas } },
      ];
    }

    const [workflows, _total] = await Promise.all([
      this.workflowModel
        .find(query)
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(offset)
        .exec(),
      this.workflowModel.countDocuments(query),
    ]);

    // Filter workflows where user has required permissions to approve
    const approveableWorkflows = [];
    for (const workflow of workflows) {
      if (await this.canUserApprove(user, workflow)) {
        approveableWorkflows.push(workflow);
      }
    }

    return {
      workflows: approveableWorkflows,
      total: approveableWorkflows.length,
    };
  }

  /**
   * Get workflow details
   */
  async getWorkflow(
    user: SACCOAuthenticatedUser,
    workflowId: string,
  ): Promise<ApprovalWorkflowDocument> {
    const workflow = await this.workflowModel.findById(workflowId);
    if (!workflow) {
      throw new NotFoundException('Workflow not found');
    }

    // Check if user has access to this workflow
    const hasAccess = await this.checkWorkflowAccess(user, workflow);
    if (!hasAccess) {
      throw new ForbiddenException('Access denied to this workflow');
    }

    return workflow;
  }

  /**
   * Cancel a pending workflow
   */
  async cancelWorkflow(
    user: SACCOAuthenticatedUser,
    workflowId: string,
    reason: string,
  ): Promise<ApprovalWorkflowDocument> {
    const workflow = await this.workflowModel.findById(workflowId);
    if (!workflow) {
      throw new NotFoundException('Workflow not found');
    }

    // Only initiator or admin can cancel
    if (
      workflow.initiatedBy !== user.userId &&
      user.serviceRole !== ServiceRole.SYSTEM_ADMIN
    ) {
      throw new ForbiddenException(
        'Only workflow initiator or system admin can cancel',
      );
    }

    if (workflow.status !== ApprovalStatus.PENDING) {
      throw new BadRequestException('Can only cancel pending workflows');
    }

    workflow.status = ApprovalStatus.CANCELLED;
    workflow.metadata.cancellationReason = reason;
    workflow.metadata.cancelledBy = user.userId;
    workflow.metadata.cancelledAt = new Date();

    const savedWorkflow = await workflow.save();

    // Emit cancellation event
    this.eventEmitter.emit('workflow.cancelled', {
      workflowId: savedWorkflow._id,
      cancelledBy: user.userId,
      reason,
    });

    return savedWorkflow;
  }

  // Private Methods

  private async validateInitiatorPermissions(
    user: SACCOAuthenticatedUser,
    request: WorkflowRequest,
  ): Promise<void> {
    // Check if user has permissions to initiate this workflow type
    const requiredPermissions = this.getWorkflowPermissions(
      request.workflowType,
    );
    const hasPermissions = this.permissionService.userHasAllPermissions(
      user,
      requiredPermissions,
      request.scope,
      request.organizationId,
      request.chamaId,
    );

    if (!hasPermissions) {
      throw new ForbiddenException(
        'Insufficient permissions to initiate this workflow',
      );
    }
  }

  private async checkSegregationRules(
    user: SACCOAuthenticatedUser,
    request: WorkflowRequest,
  ): Promise<void> {
    const applicableRules = await this.segregationRuleModel.find({
      scope: { $in: [request.scope, PermissionScope.GLOBAL] },
      isActive: true,
    });

    for (const rule of applicableRules) {
      const conflict = await this.detectSegregationConflict(
        user,
        request,
        rule,
      );
      if (conflict) {
        if (rule.enforcement.blockConflicting) {
          throw new ForbiddenException(
            `Segregation of duties violation: ${rule.description}`,
          );
        } else {
          // Log warning but allow with approval
          await this.complianceService.logComplianceEvent({
            eventType: 'segregation_violation',
            severity: RiskLevel.MEDIUM,
            description: `SoD rule violation: ${rule.ruleName}`,
            userId: user.userId,
            scope: request.scope,
            organizationId: request.organizationId,
            chamaId: request.chamaId,
          });
        }
      }
    }
  }

  private async checkTransactionLimits(
    user: SACCOAuthenticatedUser,
    request: WorkflowRequest,
  ): Promise<void> {
    if (!request.operationData.estimatedValue) {
      return; // No amount to check
    }

    const applicableLimits = await this.getApplicableTransactionLimits(
      user,
      request,
    );

    for (const limit of applicableLimits) {
      const violation = await this.checkLimitViolation(user, request, limit);
      if (violation) {
        if (!limit.overrideConditions.allowOverride) {
          throw new BadRequestException(
            `Transaction limit exceeded: ${limit.limitName}`,
          );
        }
        // Check if user can override
        const canOverride = await this.canUserOverrideLimit(user, limit);
        if (!canOverride) {
          throw new ForbiddenException(
            `Transaction limit exceeded and user cannot override: ${limit.limitName}`,
          );
        }
      }
    }
  }

  private async assessRiskLevel(request: WorkflowRequest): Promise<RiskLevel> {
    let risk = RiskLevel.LOW;

    // Assess based on amount
    if (request.operationData.estimatedValue) {
      if (request.operationData.estimatedValue > 1000000)
        risk = RiskLevel.CRITICAL;
      else if (request.operationData.estimatedValue > 100000)
        risk = RiskLevel.HIGH;
      else if (request.operationData.estimatedValue > 10000)
        risk = RiskLevel.MEDIUM;
    }

    // Assess based on operation type
    const highRiskOperations = [
      WorkflowType.ACCOUNT_CLOSURE,
      WorkflowType.LIMIT_OVERRIDE,
      WorkflowType.SYSTEM_MAINTENANCE,
    ];

    if (highRiskOperations.includes(request.workflowType)) {
      risk = RiskLevel.HIGH;
    }

    // Assess based on scope
    if (request.scope === PermissionScope.GLOBAL) {
      risk = RiskLevel.HIGH;
    }

    return risk;
  }

  private async buildApprovalChain(
    request: WorkflowRequest,
    riskLevel: RiskLevel,
  ): Promise<any> {
    const chain = {
      requiredApprovals: 1,
      requiredRoles: [GroupRole.CHAMA_LEADER] as (ServiceRole | GroupRole)[],
      requiredPermissions: [] as Permission[],
      allowSelfApproval: false,
      sequentialApproval: false,
      timeoutHours: 24,
    };

    // Adjust based on risk level
    switch (riskLevel) {
      case RiskLevel.CRITICAL:
        chain.requiredApprovals = 3;
        chain.requiredRoles = [ServiceRole.SYSTEM_ADMIN, GroupRole.SACCO_ADMIN];
        chain.allowSelfApproval = false;
        chain.sequentialApproval = true;
        chain.timeoutHours = 48;
        break;
      case RiskLevel.HIGH:
        chain.requiredApprovals = 2;
        chain.requiredRoles = [
          GroupRole.SACCO_ADMIN,
          GroupRole.SACCO_TREASURER,
        ];
        chain.allowSelfApproval = false;
        chain.timeoutHours = 24;
        break;
      case RiskLevel.MEDIUM:
        chain.requiredApprovals = 1;
        chain.requiredRoles = [GroupRole.CHAMA_LEADER, GroupRole.SACCO_MANAGER];
        chain.allowSelfApproval = true;
        chain.timeoutHours = 12;
        break;
      case RiskLevel.LOW:
        chain.requiredApprovals = 1;
        chain.requiredRoles = [GroupRole.CHAMA_TREASURER];
        chain.allowSelfApproval = true;
        chain.timeoutHours = 8;
        break;
    }

    // Adjust based on workflow type
    if (request.workflowType === WorkflowType.FINANCIAL_TRANSACTION) {
      chain.requiredPermissions.push(Permission.FINANCE_APPROVE);
    }

    return chain;
  }

  private async runComplianceChecks(_request: WorkflowRequest): Promise<any> {
    return {
      amlScreening: { status: 'passed' },
      sanctionsCheck: { status: 'passed' },
      riskAssessment: { score: 75, factors: ['amount', 'frequency'] },
      regulatoryRequirements: { kyc: true, documentation: [], approvals: [] },
    };
  }

  private generateWorkflowTags(request: WorkflowRequest): string[] {
    const tags = [
      request.workflowType,
      request.scope,
      request.metadata?.urgency || 'normal',
    ];

    if (request.operationData.estimatedValue) {
      if (request.operationData.estimatedValue > 50000) tags.push('high-value');
      if (request.operationData.estimatedValue > 10000)
        tags.push('medium-value');
    }

    return tags;
  }

  private async notifyApprovers(
    workflow: ApprovalWorkflowDocument,
  ): Promise<void> {
    // Implementation would send notifications to potential approvers
    this.eventEmitter.emit('workflow.notification_required', {
      workflowId: workflow._id,
      requiredRoles: workflow.approvalChain.requiredRoles,
      organizationId: workflow.organizationId,
      chamaId: workflow.chamaId,
    });
  }

  private async validateApproverPermissions(
    user: SACCOAuthenticatedUser,
    workflow: ApprovalWorkflowDocument,
  ): Promise<void> {
    const canApprove = await this.canUserApprove(user, workflow);
    if (!canApprove) {
      throw new ForbiddenException(
        'User does not have permission to approve this workflow',
      );
    }
  }

  private async canUserApprove(
    user: SACCOAuthenticatedUser,
    workflow: ApprovalWorkflowDocument,
  ): Promise<boolean> {
    // Check if user has required role
    const userRoles = this.getUserRoles(user, workflow.scope);
    const hasRequiredRole = workflow.approvalChain.requiredRoles.some((role) =>
      userRoles.includes(role),
    );

    if (!hasRequiredRole) return false;

    // Check if user has required permissions
    const hasRequiredPermissions = this.permissionService.userHasAllPermissions(
      user,
      workflow.approvalChain.requiredPermissions,
      workflow.scope,
      workflow.organizationId,
      workflow.chamaId,
    );

    return hasRequiredPermissions;
  }

  private async checkWorkflowCompletion(
    workflow: ApprovalWorkflowDocument,
  ): Promise<boolean> {
    const approvedCount = workflow.approvals.filter(
      (approval) => approval.status === ApprovalStatus.APPROVED,
    ).length;

    const rejectedCount = workflow.approvals.filter(
      (approval) => approval.status === ApprovalStatus.REJECTED,
    ).length;

    // If any rejection, workflow is complete (rejected)
    if (rejectedCount > 0) return true;

    // Check if required approvals met
    return approvedCount >= workflow.approvalChain.requiredApprovals;
  }

  private async executeApprovedOperation(
    workflow: ApprovalWorkflowDocument,
  ): Promise<void> {
    try {
      // Implementation would execute the actual operation
      // This is where the approved action gets performed

      workflow.executedAt = new Date();
      workflow.executedBy = 'system';
      workflow.executionResult = {
        success: true,
        transactionId: `txn-${Date.now()}`,
      };

      this.eventEmitter.emit('workflow.executed', {
        workflowId: workflow._id,
        operation: workflow.operationData.action,
        success: true,
      });
    } catch (error) {
      workflow.executionResult = {
        success: false,
        error: error.message,
      };

      this.eventEmitter.emit('workflow.execution_failed', {
        workflowId: workflow._id,
        error: error.message,
      });
    }
  }

  private getUserHighestRole(
    user: SACCOAuthenticatedUser,
    scope: PermissionScope,
  ): ServiceRole | GroupRole {
    if (scope === PermissionScope.GLOBAL) {
      return user.serviceRole;
    }

    // Get highest group role in context
    const relevantMemberships =
      user.groupMemberships?.filter((m) => {
        if (scope === PermissionScope.ORGANIZATION)
          return m.groupType === 'organization';
        if (scope === PermissionScope.CHAMA) return m.groupType === 'chama';
        return false;
      }) || [];

    if (relevantMemberships.length === 0) return user.serviceRole;

    // Return highest privilege role
    const roleHierarchy = {
      [GroupRole.SACCO_OWNER]: 1,
      [GroupRole.SACCO_ADMIN]: 2,
      [GroupRole.CHAMA_LEADER]: 3,
      [GroupRole.CHAMA_TREASURER]: 4,
      [GroupRole.CHAMA_MEMBER]: 5,
    };

    return relevantMemberships
      .map((m) => m.role)
      .sort((a, b) => (roleHierarchy[a] || 99) - (roleHierarchy[b] || 99))[0];
  }

  private getUserRoles(
    user: SACCOAuthenticatedUser,
    scope: PermissionScope,
  ): (ServiceRole | GroupRole)[] {
    const roles: (ServiceRole | GroupRole)[] = [user.serviceRole];

    if (scope !== PermissionScope.GLOBAL) {
      const groupRoles =
        user.groupMemberships
          ?.filter((m) => {
            if (scope === PermissionScope.ORGANIZATION)
              return m.groupType === 'organization';
            if (scope === PermissionScope.CHAMA) return m.groupType === 'chama';
            return false;
          })
          .map((m) => m.role) || [];

      roles.push(...groupRoles);
    }

    return roles;
  }

  private async checkWorkflowAccess(
    user: SACCOAuthenticatedUser,
    workflow: ApprovalWorkflowDocument,
  ): Promise<boolean> {
    // System admin can access all workflows
    if (user.serviceRole === ServiceRole.SYSTEM_ADMIN) return true;

    // Initiator can access their own workflows
    if (workflow.initiatedBy === user.userId) return true;

    // Check if user has access to the organization/chama
    const hasOrgAccess = user.groupMemberships?.some(
      (m) =>
        m.groupId === workflow.organizationId && m.groupType === 'organization',
    );

    const hasChamaAccess =
      workflow.chamaId &&
      user.groupMemberships?.some(
        (m) => m.groupId === workflow.chamaId && m.groupType === 'chama',
      );

    return hasOrgAccess || hasChamaAccess || false;
  }

  private getWorkflowPermissions(workflowType: WorkflowType): Permission[] {
    const permissionMap: Record<WorkflowType, Permission[]> = {
      [WorkflowType.FINANCIAL_TRANSACTION]: [
        Permission.FINANCE_DEPOSIT,
        Permission.FINANCE_WITHDRAW,
      ],
      [WorkflowType.LOAN_APPROVAL]: [Permission.LOAN_APPLY],
      [WorkflowType.USER_MANAGEMENT]: [
        Permission.USER_CREATE,
        Permission.USER_UPDATE,
      ],
      [WorkflowType.CONFIGURATION_CHANGE]: [Permission.SYSTEM_CONFIG],
      [WorkflowType.SHARES_ISSUANCE]: [Permission.SHARES_CREATE],
      [WorkflowType.MEMBER_ONBOARDING]: [Permission.USER_INVITE],
      [WorkflowType.ACCOUNT_CLOSURE]: [Permission.USER_DELETE],
      [WorkflowType.LIMIT_OVERRIDE]: [Permission.FINANCE_APPROVE],
      [WorkflowType.SYSTEM_MAINTENANCE]: [Permission.SYSTEM_CONFIG],
    };

    return permissionMap[workflowType] || [];
  }

  private async detectSegregationConflict(
    _user: SACCOAuthenticatedUser,
    _request: WorkflowRequest,
    _rule: SegregationRuleDocument,
  ): Promise<boolean> {
    // Implementation would check for SoD conflicts
    // This is a simplified version
    return false;
  }

  private async getApplicableTransactionLimits(
    user: SACCOAuthenticatedUser,
    request: WorkflowRequest,
  ): Promise<TransactionLimitDocument[]> {
    return this.transactionLimitModel.find({
      $and: [
        {
          $or: [
            { scope: PermissionScope.GLOBAL },
            { scope: request.scope, organizationId: request.organizationId },
            { scope: request.scope, chamaId: request.chamaId },
            { scope: PermissionScope.PERSONAL, userId: user.userId },
          ],
        },
        { isActive: true },
        { effectiveFrom: { $lte: new Date() } },
        {
          $or: [
            { effectiveUntil: { $exists: false } },
            { effectiveUntil: { $gte: new Date() } },
          ],
        },
      ],
    });
  }

  private async checkLimitViolation(
    user: SACCOAuthenticatedUser,
    request: WorkflowRequest,
    limit: TransactionLimitDocument,
  ): Promise<boolean> {
    const amount = request.operationData.estimatedValue || 0;
    return amount > limit.limits.maxTransactionAmount;
  }

  private async canUserOverrideLimit(
    user: SACCOAuthenticatedUser,
    limit: TransactionLimitDocument,
  ): Promise<boolean> {
    if (!limit.overrideConditions.allowOverride) return false;

    const userRoles = [
      user.serviceRole,
      ...this.getUserRoles(user, PermissionScope.GLOBAL),
    ];
    const hasOverrideRole = limit.overrideConditions.overrideRoles.some(
      (role) => userRoles.includes(role),
    );

    const hasOverridePermissions = this.permissionService.userHasAllPermissions(
      user,
      limit.overrideConditions.overridePermissions,
      PermissionScope.GLOBAL,
    );

    return hasOverrideRole && hasOverridePermissions;
  }
}
