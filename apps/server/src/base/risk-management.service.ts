import {
  Injectable,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { EventEmitter2 } from '@nestjs/event-emitter';
import {
  TransactionLimit,
  TransactionLimitDocument,
  RiskLevel,
  SACCOAuthenticatedUser,
  Permission,
  PermissionScope,
  ServiceRole,
  GroupRole,
} from '../common';
import { ComplianceService } from './compliance.service';
import { AuditService } from './audit.service';

export interface RiskAssessment {
  riskScore: number; // 0-100
  riskLevel: RiskLevel;
  factors: Array<{
    factor: string;
    weight: number;
    score: number;
    description: string;
  }>;
  mitigationActions: string[];
  automaticActions: string[];
  requiresApproval: boolean;
  requiresReview: boolean;
}

export interface TransactionRisk {
  amount: number;
  currency: string;
  transactionType: string;
  frequency: number; // transactions in last 24h
  userRiskProfile: 'low' | 'medium' | 'high';
  counterpartyRisk?: 'low' | 'medium' | 'high';
  geographicRisk?: 'low' | 'medium' | 'high';
  timeOfDay: number; // hour 0-23
  isWeekend: boolean;
  isHoliday?: boolean;
}

export interface LimitViolation {
  limitId: string;
  limitName: string;
  limitType: 'transaction' | 'daily' | 'weekly' | 'monthly' | 'yearly';
  currentValue: number;
  limitValue: number;
  violationPercentage: number;
  canOverride: boolean;
  requiresApproval: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Risk Management and Transaction Limits Service
 * Implements comprehensive risk controls and monitoring
 */
@Injectable()
export class RiskManagementService {
  private riskFactorWeights = {
    amount: 0.3,
    frequency: 0.2,
    userProfile: 0.2,
    timePattern: 0.1,
    geographic: 0.1,
    counterparty: 0.1,
  };

  constructor(
    @InjectModel(TransactionLimit.name)
    private transactionLimitModel: Model<TransactionLimitDocument>,
    private complianceService: ComplianceService,
    private auditService: AuditService,
    private eventEmitter: EventEmitter2,
  ) {
    this.initializeDefaultLimits();
  }

  /**
   * Assess transaction risk
   */
  async assessTransactionRisk(
    user: SACCOAuthenticatedUser,
    transactionData: TransactionRisk,
    scope: PermissionScope,
    organizationId?: string,
    chamaId?: string,
  ): Promise<RiskAssessment> {
    const factors = [];
    let totalScore = 0;

    // Amount-based risk assessment
    const amountFactor = this.assessAmountRisk(transactionData.amount);
    factors.push(amountFactor);
    totalScore += amountFactor.score * this.riskFactorWeights.amount;

    // Frequency-based risk assessment
    const frequencyFactor = this.assessFrequencyRisk(transactionData.frequency);
    factors.push(frequencyFactor);
    totalScore += frequencyFactor.score * this.riskFactorWeights.frequency;

    // User profile risk assessment
    const userProfileFactor = this.assessUserProfileRisk(
      transactionData.userRiskProfile,
    );
    factors.push(userProfileFactor);
    totalScore += userProfileFactor.score * this.riskFactorWeights.userProfile;

    // Time pattern risk assessment
    const timePatternFactor = this.assessTimePatternRisk(
      transactionData.timeOfDay,
      transactionData.isWeekend,
      transactionData.isHoliday,
    );
    factors.push(timePatternFactor);
    totalScore += timePatternFactor.score * this.riskFactorWeights.timePattern;

    // Geographic risk assessment
    if (transactionData.geographicRisk) {
      const geographicFactor = this.assessGeographicRisk(
        transactionData.geographicRisk,
      );
      factors.push(geographicFactor);
      totalScore += geographicFactor.score * this.riskFactorWeights.geographic;
    }

    // Counterparty risk assessment
    if (transactionData.counterpartyRisk) {
      const counterpartyFactor = this.assessCounterpartyRisk(
        transactionData.counterpartyRisk,
      );
      factors.push(counterpartyFactor);
      totalScore +=
        counterpartyFactor.score * this.riskFactorWeights.counterparty;
    }

    const riskScore = Math.min(100, Math.max(0, totalScore));
    const riskLevel = this.calculateRiskLevel(riskScore);

    const assessment: RiskAssessment = {
      riskScore,
      riskLevel,
      factors,
      mitigationActions: this.generateMitigationActions(riskLevel, factors),
      automaticActions: this.generateAutomaticActions(riskLevel, riskScore),
      requiresApproval: this.requiresApproval(riskLevel, riskScore),
      requiresReview: this.requiresReview(riskLevel, riskScore),
    };

    // Log risk assessment
    await this.auditService.logAuditEvent({
      userId: user.userId,
      action: 'RISK_ASSESSMENT_PERFORMED',
      resourceType: 'transaction',
      scope,
      organizationId,
      chamaId,
      complianceContext: {
        riskLevel: riskLevel,
        sensitiveData: false,
        approvalRequired: this.requiresApproval(riskLevel, riskScore),
      },
      businessContext: {
        amount: transactionData.amount,
        currency: transactionData.currency,
        transactionType: transactionData.transactionType,
      },
    });

    // Emit risk assessment event
    this.eventEmitter.emit('risk.assessment_completed', {
      userId: user.userId,
      riskScore,
      riskLevel,
      transactionAmount: transactionData.amount,
    });

    return assessment;
  }

  /**
   * Check transaction limits
   */
  async checkTransactionLimits(
    user: SACCOAuthenticatedUser,
    amount: number,
    currency: string,
    operationType: string,
    scope: PermissionScope,
    organizationId?: string,
    chamaId?: string,
  ): Promise<{
    violations: LimitViolation[];
    canProceed: boolean;
    requiresApproval: boolean;
  }> {
    // Get applicable limits
    const applicableLimits = await this.getApplicableLimits(
      user,
      scope,
      organizationId,
      chamaId,
      operationType,
    );

    const violations: LimitViolation[] = [];
    let canProceed = true;
    let requiresApproval = false;

    for (const limit of applicableLimits) {
      if (limit.currency !== currency) continue;

      // Check per-transaction limit
      if (amount > limit.limits.maxTransactionAmount) {
        const violation: LimitViolation = {
          limitId: limit._id.toString(),
          limitName: limit.limitName,
          limitType: 'transaction',
          currentValue: amount,
          limitValue: limit.limits.maxTransactionAmount,
          violationPercentage:
            ((amount - limit.limits.maxTransactionAmount) /
              limit.limits.maxTransactionAmount) *
            100,
          canOverride: limit.overrideConditions.allowOverride,
          requiresApproval: limit.overrideConditions.requiresApproval,
          severity: this.calculateViolationSeverity(
            amount,
            limit.limits.maxTransactionAmount,
          ),
        };

        violations.push(violation);

        if (!limit.overrideConditions.allowOverride) {
          canProceed = false;
        } else if (limit.overrideConditions.requiresApproval) {
          requiresApproval = true;
        }
      }

      // Check periodic limits (daily, weekly, monthly)
      const periodicViolations = await this.checkPeriodicLimits(
        user,
        amount,
        limit,
        scope,
      );
      violations.push(...periodicViolations);

      // Update approval requirements based on periodic violations
      periodicViolations.forEach((violation) => {
        if (!violation.canOverride) canProceed = false;
        if (violation.requiresApproval) requiresApproval = true;
      });
    }

    // Log limit check
    await this.auditService.logAuditEvent({
      userId: user.userId,
      action: 'TRANSACTION_LIMITS_CHECKED',
      resourceType: 'transaction_limit',
      scope,
      organizationId,
      chamaId,
      complianceContext: {
        sensitiveData: false,
        approvalRequired: requiresApproval,
      },
      businessContext: {
        amount,
        currency,
        transactionType: operationType,
      },
    });

    return { violations, canProceed, requiresApproval };
  }

  /**
   * Create transaction limit
   */
  async createTransactionLimit(
    user: SACCOAuthenticatedUser,
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
  ): Promise<TransactionLimitDocument> {
    // Validate permissions
    const canCreateLimits = this.validateLimitCreationPermissions(
      user,
      limitData.scope,
    );
    if (!canCreateLimits) {
      throw new ForbiddenException(
        'Insufficient permissions to create transaction limits',
      );
    }

    const limit = new this.transactionLimitModel({
      ...limitData,
      isActive: true,
      createdBy: user.userId,
    });

    const savedLimit = await limit.save();

    // Log audit event
    await this.auditService.logAuditEvent({
      userId: user.userId,
      action: 'TRANSACTION_LIMIT_CREATED',
      resourceType: 'transaction_limit',
      resourceId: savedLimit._id.toString(),
      scope: limitData.scope,
      organizationId: limitData.organizationId,
      chamaId: limitData.chamaId,
    });

    return savedLimit;
  }

  /**
   * Update transaction limit
   */
  async updateTransactionLimit(
    user: SACCOAuthenticatedUser,
    limitId: string,
    updateData: Partial<TransactionLimit>,
  ): Promise<TransactionLimitDocument> {
    const limit = await this.transactionLimitModel.findById(limitId);
    if (!limit) {
      throw new BadRequestException('Transaction limit not found');
    }

    // Validate permissions
    const canUpdateLimits = this.validateLimitUpdatePermissions(
      user,
      limit.scope,
    );
    if (!canUpdateLimits) {
      throw new ForbiddenException(
        'Insufficient permissions to update transaction limits',
      );
    }

    const updatedLimit = await this.transactionLimitModel.findByIdAndUpdate(
      limitId,
      updateData,
      { new: true, runValidators: true },
    );

    // Log audit event
    await this.auditService.logAuditEvent({
      userId: user.userId,
      action: 'TRANSACTION_LIMIT_UPDATED',
      resourceType: 'transaction_limit',
      resourceId: limitId,
      scope: limit.scope,
      organizationId: limit.organizationId,
      chamaId: limit.chamaId,
    });

    return updatedLimit!;
  }

  /**
   * Get transaction limits
   */
  async getTransactionLimits(
    user: SACCOAuthenticatedUser,
    scope?: PermissionScope,
    organizationId?: string,
    chamaId?: string,
    isActive?: boolean,
  ): Promise<TransactionLimitDocument[]> {
    const query: any = {};

    if (scope) query.scope = scope;
    if (organizationId) query.organizationId = organizationId;
    if (chamaId) query.chamaId = chamaId;
    if (isActive !== undefined) query.isActive = isActive;

    // Filter based on user permissions
    if (user.serviceRole !== ServiceRole.SYSTEM_ADMIN) {
      // Users can only see limits they have access to
      const accessibleOrgs =
        user.groupMemberships
          ?.filter((m) => m.groupType === 'organization')
          .map((m) => m.groupId) || [];

      const accessibleChamas =
        user.groupMemberships
          ?.filter((m) => m.groupType === 'chama')
          .map((m) => m.groupId) || [];

      query.$or = [
        { scope: PermissionScope.GLOBAL },
        { organizationId: { $in: accessibleOrgs } },
        { chamaId: { $in: accessibleChamas } },
        { userId: user.userId },
      ];
    }

    return this.transactionLimitModel.find(query).sort({ createdAt: -1 });
  }

  /**
   * Generate risk report
   */
  async generateRiskReport(
    scope: PermissionScope,
    organizationId?: string,
    chamaId?: string,
    days: number = 30,
  ): Promise<{
    summary: {
      totalTransactions: number;
      highRiskTransactions: number;
      blockedTransactions: number;
      limitViolations: number;
      averageRiskScore: number;
    };
    trends: {
      riskScoreOverTime: Array<{ date: string; avgRiskScore: number }>;
      violationsByType: Record<string, number>;
      topRiskFactors: Array<{ factor: string; frequency: number }>;
    };
    recommendations: string[];
  }> {
    const endDate = new Date();
    const startDate = new Date(endDate.getTime() - days * 24 * 60 * 60 * 1000);

    // Get risk assessment logs
    const { logs: riskLogs } = await this.auditService.getAuditLogs({
      action: 'RISK_ASSESSMENT_PERFORMED',
      scope,
      organizationId,
      chamaId,
      startDate,
      endDate,
      limit: 10000,
    });

    // Get limit violation logs
    const { logs: violationLogs } = await this.auditService.getAuditLogs({
      action: 'TRANSACTION_LIMITS_CHECKED',
      scope,
      organizationId,
      chamaId,
      startDate,
      endDate,
      limit: 10000,
    });

    // Calculate summary metrics
    const summary = {
      totalTransactions: riskLogs.length,
      highRiskTransactions: riskLogs.filter(
        (log) =>
          log.complianceContext?.riskLevel === 'high' ||
          log.complianceContext?.riskLevel === 'critical',
      ).length,
      blockedTransactions: 0, // Would be calculated from actual transaction data
      limitViolations: violationLogs.length,
      averageRiskScore: 0, // Would be calculated from risk scores
    };

    // Generate trends (mock data for demo)
    const trends = {
      riskScoreOverTime: this.generateRiskScoreTrend(startDate, endDate),
      violationsByType: {
        'Daily Limit': 15,
        'Transaction Limit': 8,
        'Monthly Limit': 3,
      },
      topRiskFactors: [
        { factor: 'Amount', frequency: 25 },
        { factor: 'Frequency', frequency: 18 },
        { factor: 'Time Pattern', frequency: 12 },
      ],
    };

    // Generate recommendations
    const recommendations = this.generateRiskRecommendations(summary, trends);

    return { summary, trends, recommendations };
  }

  /**
   * Monitor real-time risk patterns
   */
  async monitorRealTimeRisk(
    scope: PermissionScope,
    organizationId?: string,
    chamaId?: string,
  ): Promise<{
    currentRiskLevel: RiskLevel;
    activeAlerts: Array<{
      type: string;
      severity: string;
      message: string;
      timestamp: Date;
    }>;
    recentHighRiskTransactions: Array<{
      userId: string;
      amount: number;
      riskScore: number;
      timestamp: Date;
    }>;
    systemLoad: {
      transactionsPerMinute: number;
      riskAssessmentsPerMinute: number;
      blockedTransactions: number;
    };
  }> {
    // Get recent risk events (last hour)
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

    const { logs: recentLogs } = await this.auditService.getAuditLogs({
      action: 'RISK_ASSESSMENT_PERFORMED',
      scope,
      organizationId,
      chamaId,
      startDate: oneHourAgo,
      limit: 1000,
    });

    // Calculate current risk level
    const highRiskCount = recentLogs.filter(
      (log) =>
        log.complianceContext?.riskLevel === 'high' ||
        log.complianceContext?.riskLevel === 'critical',
    ).length;

    const currentRiskLevel = this.calculateSystemRiskLevel(
      highRiskCount,
      recentLogs.length,
    );

    // Generate active alerts (mock data)
    const activeAlerts = [
      {
        type: 'High Transaction Volume',
        severity: 'medium',
        message: 'Transaction volume 20% above normal',
        timestamp: new Date(),
      },
    ];

    // Get recent high-risk transactions (mock data)
    const recentHighRiskTransactions = [
      {
        userId: 'user-001',
        amount: 50000,
        riskScore: 85,
        timestamp: new Date(),
      },
    ];

    // Calculate system load metrics
    const systemLoad = {
      transactionsPerMinute: Math.round(recentLogs.length / 60),
      riskAssessmentsPerMinute: Math.round(recentLogs.length / 60),
      blockedTransactions: 0, // Would be calculated from actual data
    };

    return {
      currentRiskLevel,
      activeAlerts,
      recentHighRiskTransactions,
      systemLoad,
    };
  }

  // Private Methods

  private async initializeDefaultLimits(): Promise<void> {
    const defaultLimits = [
      {
        limitName: 'SACCO Daily Transaction Limit',
        scope: PermissionScope.ORGANIZATION,
        applicableRoles: [GroupRole.CHAMA_MEMBER, GroupRole.CHAMA_TREASURER],
        currency: 'KES',
        limits: {
          maxTransactionAmount: 100000,
          dailyLimit: 500000,
          monthlyLimit: 2000000,
          dailyTransactionCount: 10,
        },
        applicableOperations: ['deposit', 'withdraw', 'transfer'],
        overrideConditions: {
          allowOverride: true,
          overrideRoles: [GroupRole.SACCO_ADMIN, GroupRole.SACCO_TREASURER],
          overridePermissions: [Permission.FINANCE_APPROVE],
          requiresApproval: true,
          maxOverridePercentage: 50,
        },
        isActive: true,
        effectiveFrom: new Date(),
        createdBy: 'system',
      },
      {
        limitName: 'Chama Member Transaction Limit',
        scope: PermissionScope.CHAMA,
        applicableRoles: [GroupRole.CHAMA_MEMBER],
        currency: 'KES',
        limits: {
          maxTransactionAmount: 25000,
          dailyLimit: 50000,
          monthlyLimit: 200000,
          dailyTransactionCount: 5,
        },
        applicableOperations: ['deposit', 'withdraw'],
        overrideConditions: {
          allowOverride: true,
          overrideRoles: [GroupRole.CHAMA_LEADER, GroupRole.CHAMA_TREASURER],
          overridePermissions: [Permission.FINANCE_APPROVE],
          requiresApproval: true,
          maxOverridePercentage: 25,
        },
        isActive: true,
        effectiveFrom: new Date(),
        createdBy: 'system',
      },
    ];

    for (const limitData of defaultLimits) {
      const existing = await this.transactionLimitModel.findOne({
        limitName: limitData.limitName,
      });

      if (!existing) {
        await this.transactionLimitModel.create(limitData);
      }
    }
  }

  private assessAmountRisk(amount: number): any {
    let score = 0;
    let description = '';

    if (amount < 1000) {
      score = 10;
      description = 'Low amount transaction';
    } else if (amount < 10000) {
      score = 25;
      description = 'Medium amount transaction';
    } else if (amount < 50000) {
      score = 50;
      description = 'High amount transaction';
    } else {
      score = 80;
      description = 'Very high amount transaction';
    }

    return {
      factor: 'Amount',
      weight: this.riskFactorWeights.amount,
      score,
      description,
    };
  }

  private assessFrequencyRisk(frequency: number): any {
    let score = 0;
    let description = '';

    if (frequency <= 2) {
      score = 10;
      description = 'Normal transaction frequency';
    } else if (frequency <= 5) {
      score = 30;
      description = 'Moderate transaction frequency';
    } else if (frequency <= 10) {
      score = 60;
      description = 'High transaction frequency';
    } else {
      score = 90;
      description = 'Very high transaction frequency';
    }

    return {
      factor: 'Frequency',
      weight: this.riskFactorWeights.frequency,
      score,
      description,
    };
  }

  private assessUserProfileRisk(userRiskProfile: string): any {
    const scoreMap = {
      low: 10,
      medium: 40,
      high: 80,
    };

    return {
      factor: 'User Profile',
      weight: this.riskFactorWeights.userProfile,
      score: scoreMap[userRiskProfile] || 40,
      description: `User has ${userRiskProfile} risk profile`,
    };
  }

  private assessTimePatternRisk(
    timeOfDay: number,
    isWeekend: boolean,
    isHoliday?: boolean,
  ): any {
    let score = 20; // Base score
    let description = 'Normal business hours';

    // High risk for transactions outside business hours (8 AM - 6 PM)
    if (timeOfDay < 8 || timeOfDay > 18) {
      score += 30;
      description = 'Transaction outside business hours';
    }

    // Additional risk for weekends
    if (isWeekend) {
      score += 20;
      description += ', weekend transaction';
    }

    // Additional risk for holidays
    if (isHoliday) {
      score += 25;
      description += ', holiday transaction';
    }

    return {
      factor: 'Time Pattern',
      weight: this.riskFactorWeights.timePattern,
      score: Math.min(100, score),
      description,
    };
  }

  private assessGeographicRisk(geographicRisk: string): any {
    const scoreMap = {
      low: 15,
      medium: 45,
      high: 80,
    };

    return {
      factor: 'Geographic',
      weight: this.riskFactorWeights.geographic,
      score: scoreMap[geographicRisk] || 45,
      description: `${geographicRisk} geographic risk location`,
    };
  }

  private assessCounterpartyRisk(counterpartyRisk: string): any {
    const scoreMap = {
      low: 10,
      medium: 40,
      high: 85,
    };

    return {
      factor: 'Counterparty',
      weight: this.riskFactorWeights.counterparty,
      score: scoreMap[counterpartyRisk] || 40,
      description: `${counterpartyRisk} risk counterparty`,
    };
  }

  private calculateRiskLevel(riskScore: number): RiskLevel {
    if (riskScore >= 80) return RiskLevel.CRITICAL;
    if (riskScore >= 60) return RiskLevel.HIGH;
    if (riskScore >= 40) return RiskLevel.MEDIUM;
    return RiskLevel.LOW;
  }

  private generateMitigationActions(
    riskLevel: RiskLevel,
    factors: any[],
  ): string[] {
    const actions = [];

    if (riskLevel === RiskLevel.CRITICAL || riskLevel === RiskLevel.HIGH) {
      actions.push('Require additional authorization');
      actions.push('Enhanced monitoring for 24 hours');
      actions.push('Contact customer for verification');
    }

    if (riskLevel === RiskLevel.MEDIUM) {
      actions.push('Apply enhanced due diligence');
      actions.push('Monitor for related transactions');
    }

    // Add factor-specific mitigations
    factors.forEach((factor) => {
      if (factor.factor === 'Amount' && factor.score > 60) {
        actions.push('Verify source of funds');
      }
      if (factor.factor === 'Frequency' && factor.score > 70) {
        actions.push('Implement transaction cooling period');
      }
    });

    return [...new Set(actions)]; // Remove duplicates
  }

  private generateAutomaticActions(
    riskLevel: RiskLevel,
    riskScore: number,
  ): string[] {
    const actions = [];

    if (riskLevel === RiskLevel.CRITICAL) {
      actions.push('Block transaction pending review');
      actions.push('Alert compliance team');
      actions.push('Freeze account temporarily');
    } else if (riskLevel === RiskLevel.HIGH) {
      actions.push('Hold transaction for review');
      actions.push('Send alert to risk team');
    } else if (riskLevel === RiskLevel.MEDIUM && riskScore > 50) {
      actions.push('Flag for monitoring');
    }

    return actions;
  }

  private requiresApproval(riskLevel: RiskLevel, riskScore: number): boolean {
    return (
      riskLevel === RiskLevel.CRITICAL ||
      riskLevel === RiskLevel.HIGH ||
      (riskLevel === RiskLevel.MEDIUM && riskScore > 55)
    );
  }

  private requiresReview(riskLevel: RiskLevel, riskScore: number): boolean {
    return (
      riskLevel === RiskLevel.HIGH ||
      riskLevel === RiskLevel.CRITICAL ||
      riskScore > 70
    );
  }

  private async getApplicableLimits(
    user: SACCOAuthenticatedUser,
    scope: PermissionScope,
    organizationId?: string,
    chamaId?: string,
    operationType?: string,
  ): Promise<TransactionLimitDocument[]> {
    const query: any = {
      isActive: true,
      effectiveFrom: { $lte: new Date() },
      $or: [
        { effectiveUntil: { $exists: false } },
        { effectiveUntil: { $gte: new Date() } },
      ],
    };

    // Add scope filters
    query.$or = [
      { scope: PermissionScope.GLOBAL },
      { scope: scope, organizationId: organizationId },
      { scope: PermissionScope.CHAMA, chamaId: chamaId },
      { scope: PermissionScope.PERSONAL, userId: user.userId },
    ];

    // Filter by operation type
    if (operationType) {
      query.applicableOperations = operationType;
    }

    const limits = await this.transactionLimitModel.find(query);

    // Filter by user roles
    return limits.filter((limit) => {
      const userRoles: (ServiceRole | GroupRole)[] = [user.serviceRole];
      if (user.groupMemberships) {
        userRoles.push(...user.groupMemberships.map((m) => m.role));
      }
      return limit.applicableRoles.some((role) => userRoles.includes(role));
    });
  }

  private async checkPeriodicLimits(
    user: SACCOAuthenticatedUser,
    amount: number,
    limit: TransactionLimitDocument,
    _scope: PermissionScope,
  ): Promise<LimitViolation[]> {
    const violations: LimitViolation[] = [];

    // This would check actual transaction history
    // For demo purposes, using mock current usage
    const currentUsage = {
      daily: 25000,
      weekly: 75000,
      monthly: 150000,
    };

    // Check daily limit
    if (
      limit.limits.dailyLimit &&
      currentUsage.daily + amount > limit.limits.dailyLimit
    ) {
      violations.push({
        limitId: limit._id.toString(),
        limitName: limit.limitName,
        limitType: 'daily',
        currentValue: currentUsage.daily + amount,
        limitValue: limit.limits.dailyLimit,
        violationPercentage:
          ((currentUsage.daily + amount - limit.limits.dailyLimit) /
            limit.limits.dailyLimit) *
          100,
        canOverride: limit.overrideConditions.allowOverride,
        requiresApproval: limit.overrideConditions.requiresApproval,
        severity: this.calculateViolationSeverity(
          currentUsage.daily + amount,
          limit.limits.dailyLimit,
        ),
      });
    }

    // Check monthly limit
    if (
      limit.limits.monthlyLimit &&
      currentUsage.monthly + amount > limit.limits.monthlyLimit
    ) {
      violations.push({
        limitId: limit._id.toString(),
        limitName: limit.limitName,
        limitType: 'monthly',
        currentValue: currentUsage.monthly + amount,
        limitValue: limit.limits.monthlyLimit,
        violationPercentage:
          ((currentUsage.monthly + amount - limit.limits.monthlyLimit) /
            limit.limits.monthlyLimit) *
          100,
        canOverride: limit.overrideConditions.allowOverride,
        requiresApproval: limit.overrideConditions.requiresApproval,
        severity: this.calculateViolationSeverity(
          currentUsage.monthly + amount,
          limit.limits.monthlyLimit,
        ),
      });
    }

    return violations;
  }

  private calculateViolationSeverity(
    currentValue: number,
    limitValue: number,
  ): 'low' | 'medium' | 'high' | 'critical' {
    const violationPercentage =
      ((currentValue - limitValue) / limitValue) * 100;

    if (violationPercentage >= 100) return 'critical';
    if (violationPercentage >= 50) return 'high';
    if (violationPercentage >= 25) return 'medium';
    return 'low';
  }

  private validateLimitCreationPermissions(
    user: SACCOAuthenticatedUser,
    scope: PermissionScope,
  ): boolean {
    if (user.serviceRole === ServiceRole.SYSTEM_ADMIN) return true;

    // Check if user has appropriate permissions for the scope
    if (scope === PermissionScope.GLOBAL) {
      return false; // Only SYSTEM_ADMIN can create global limits
    }

    return user.serviceRole === ServiceRole.ADMIN;
  }

  private validateLimitUpdatePermissions(
    user: SACCOAuthenticatedUser,
    scope: PermissionScope,
  ): boolean {
    return this.validateLimitCreationPermissions(user, scope);
  }

  private generateRiskScoreTrend(
    startDate: Date,
    endDate: Date,
  ): Array<{ date: string; avgRiskScore: number }> {
    const trend = [];
    const currentDate = new Date(startDate);

    while (currentDate <= endDate) {
      trend.push({
        date: currentDate.toISOString().split('T')[0],
        avgRiskScore: 30 + Math.random() * 40, // Mock data: 30-70 range
      });
      currentDate.setDate(currentDate.getDate() + 1);
    }

    return trend;
  }

  private generateRiskRecommendations(summary: any, trends: any): string[] {
    const recommendations = [];

    if (summary.highRiskTransactions / summary.totalTransactions > 0.1) {
      recommendations.push('Consider tightening risk assessment criteria');
    }

    if (summary.limitViolations > 20) {
      recommendations.push('Review and adjust transaction limits');
    }

    if (trends.topRiskFactors[0]?.factor === 'Amount') {
      recommendations.push('Implement amount-based risk scoring adjustments');
    }

    recommendations.push('Regular review of risk policies recommended');

    return recommendations;
  }

  private calculateSystemRiskLevel(
    highRiskCount: number,
    totalCount: number,
  ): RiskLevel {
    if (totalCount === 0) return RiskLevel.LOW;

    const highRiskRatio = highRiskCount / totalCount;

    if (highRiskRatio >= 0.2) return RiskLevel.CRITICAL;
    if (highRiskRatio >= 0.1) return RiskLevel.HIGH;
    if (highRiskRatio >= 0.05) return RiskLevel.MEDIUM;
    return RiskLevel.LOW;
  }
}
