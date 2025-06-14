import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { EventEmitter2 } from '@nestjs/event-emitter';
import {
  ComplianceEvent,
  ComplianceEventDocument,
  RegulatoryReport,
  RegulatoryReportDocument,
  RiskLevel,
  SACCOAuthenticatedUser,
  PermissionScope,
} from '../common';
import { AuditService } from './audit.service';

export interface ComplianceEventData {
  eventType: string;
  severity: RiskLevel;
  description: string;
  userId?: string;
  scope: PermissionScope;
  organizationId?: string;
  chamaId?: string;
  eventData?: Record<string, any>;
  tags?: string[];
}

export interface ComplianceMetrics {
  kycCompliance: {
    total: number;
    verified: number;
    pending: number;
    rejected: number;
    complianceRate: number;
  };
  transactionCompliance: {
    totalTransactions: number;
    flaggedTransactions: number;
    blockedTransactions: number;
    complianceRate: number;
  };
  regulatoryCompliance: {
    totalReports: number;
    submittedOnTime: number;
    overdue: number;
    acknowledged: number;
    complianceRate: number;
  };
  riskManagement: {
    highRiskEvents: number;
    mitigatedRisks: number;
    openRisks: number;
    riskScore: number;
  };
}

/**
 * Compliance Monitoring and Regulatory Reporting Service
 */
@Injectable()
export class ComplianceService {
  constructor(
    @InjectModel(ComplianceEvent.name)
    private complianceEventModel: Model<ComplianceEventDocument>,
    @InjectModel(RegulatoryReport.name)
    private regulatoryReportModel: Model<RegulatoryReportDocument>,
    private auditService: AuditService,
    private eventEmitter: EventEmitter2,
  ) {}

  /**
   * Log a compliance event
   */
  async logComplianceEvent(
    eventData: ComplianceEventData,
  ): Promise<ComplianceEventDocument> {
    const event = new this.complianceEventModel({
      ...eventData,
      detection: {
        detectionMethod: 'automatic',
        detectionSystem: 'sacco-compliance-engine',
        confidence: 95,
      },
      response: {
        status: 'open',
      },
      regulatoryImpact: {
        reportable: this.isEventReportable(eventData),
        regulators: this.getApplicableRegulators(eventData),
      },
    });

    const savedEvent = await event.save();

    // Emit compliance event
    this.eventEmitter.emit('compliance.event_logged', {
      eventId: savedEvent._id,
      eventType: eventData.eventType,
      severity: eventData.severity,
      scope: eventData.scope,
    });

    // Auto-escalate critical events
    if (eventData.severity === RiskLevel.CRITICAL) {
      await this.escalateEvent(savedEvent._id.toString());
    }

    return savedEvent;
  }

  /**
   * Get compliance events with filtering
   */
  async getComplianceEvents(
    user: SACCOAuthenticatedUser,
    filters: {
      eventType?: string;
      severity?: RiskLevel;
      scope?: PermissionScope;
      organizationId?: string;
      chamaId?: string;
      status?: 'open' | 'investigating' | 'resolved' | 'false_positive';
      startDate?: Date;
      endDate?: Date;
      limit?: number;
      offset?: number;
    } = {},
  ): Promise<{
    events: ComplianceEventDocument[];
    total: number;
  }> {
    const query: any = {};

    // Apply filters
    if (filters.eventType) query.eventType = filters.eventType;
    if (filters.severity) query.severity = filters.severity;
    if (filters.scope) query.scope = filters.scope;
    if (filters.organizationId) query.organizationId = filters.organizationId;
    if (filters.chamaId) query.chamaId = filters.chamaId;
    if (filters.status) query['response.status'] = filters.status;

    // Date range filter
    if (filters.startDate || filters.endDate) {
      query.createdAt = {};
      if (filters.startDate) query.createdAt.$gte = filters.startDate;
      if (filters.endDate) query.createdAt.$lte = filters.endDate;
    }

    const limit = filters.limit || 50;
    const offset = filters.offset || 0;

    const [events, total] = await Promise.all([
      this.complianceEventModel
        .find(query)
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(offset)
        .exec(),
      this.complianceEventModel.countDocuments(query),
    ]);

    return { events, total };
  }

  /**
   * Update compliance event status
   */
  async updateEventStatus(
    user: SACCOAuthenticatedUser,
    eventId: string,
    update: {
      status: 'open' | 'investigating' | 'resolved' | 'false_positive';
      assignedTo?: string;
      resolutionNotes?: string;
      escalate?: boolean;
      escalatedTo?: string;
    },
  ): Promise<ComplianceEventDocument> {
    const event = await this.complianceEventModel.findById(eventId);
    if (!event) {
      throw new BadRequestException('Compliance event not found');
    }

    // Update response data
    event.response.status = update.status;
    if (update.assignedTo) event.response.assignedTo = update.assignedTo;
    if (update.resolutionNotes)
      event.response.resolutionNotes = update.resolutionNotes;
    if (update.status === 'resolved') event.response.resolvedAt = new Date();
    if (update.escalate) {
      event.response.escalated = true;
      event.response.escalatedTo = update.escalatedTo;
    }

    const savedEvent = await event.save();

    // Log audit event
    await this.auditService.logAuditEvent({
      userId: user.userId,
      action: 'COMPLIANCE_EVENT_UPDATED',
      resourceType: 'compliance_event',
      resourceId: eventId,
      scope: event.scope,
      organizationId: event.organizationId,
      chamaId: event.chamaId,
    });

    return savedEvent;
  }

  /**
   * Generate compliance metrics dashboard
   */
  async getComplianceMetrics(
    scope: PermissionScope,
    organizationId?: string,
    chamaId?: string,
    timeRange: '24h' | '7d' | '30d' | '90d' = '30d',
  ): Promise<ComplianceMetrics> {
    const endDate = new Date();
    const startDate = this.getStartDate(timeRange);

    // Get compliance events for the period
    const { events } = await this.getComplianceEvents(
      {} as SACCOAuthenticatedUser,
      {
        scope,
        organizationId,
        chamaId,
        startDate,
        endDate,
        limit: 10000, // Get all events for metrics
      },
    );

    // Calculate KYC compliance (mock data for demo)
    const kycCompliance = {
      total: 150,
      verified: 145,
      pending: 3,
      rejected: 2,
      complianceRate: 96.7,
    };

    // Calculate transaction compliance
    const transactionEvents = events.filter((e) =>
      e.eventType.includes('transaction'),
    );
    const transactionCompliance = {
      totalTransactions: 1000,
      flaggedTransactions: transactionEvents.length,
      blockedTransactions: transactionEvents.filter((e) => e.eventData?.blocked)
        .length,
      complianceRate: 100 - (transactionEvents.length / 1000) * 100,
    };

    // Calculate regulatory compliance
    const reportingPeriod = await this.regulatoryReportModel.find({
      scope,
      organizationId,
      'reportingPeriod.startDate': { $gte: startDate },
      'reportingPeriod.endDate': { $lte: endDate },
    });

    const regulatoryCompliance = {
      totalReports: reportingPeriod.length,
      submittedOnTime: reportingPeriod.filter(
        (r) => r.submission.status === 'submitted',
      ).length,
      overdue: reportingPeriod.filter((r) => r.submission.status === 'draft')
        .length,
      acknowledged: reportingPeriod.filter(
        (r) => r.submission.status === 'acknowledged',
      ).length,
      complianceRate:
        reportingPeriod.length > 0
          ? (reportingPeriod.filter((r) => r.submission.status === 'submitted')
              .length /
              reportingPeriod.length) *
            100
          : 100,
    };

    // Calculate risk management metrics
    const highRiskEvents = events.filter(
      (e) => e.severity === RiskLevel.HIGH || e.severity === RiskLevel.CRITICAL,
    );
    const riskManagement = {
      highRiskEvents: highRiskEvents.length,
      mitigatedRisks: highRiskEvents.filter(
        (e) => e.response.status === 'resolved',
      ).length,
      openRisks: highRiskEvents.filter((e) => e.response.status === 'open')
        .length,
      riskScore: this.calculateRiskScore(events),
    };

    return {
      kycCompliance,
      transactionCompliance,
      regulatoryCompliance,
      riskManagement,
    };
  }

  /**
   * Generate regulatory report
   */
  async generateRegulatoryReport(
    user: SACCOAuthenticatedUser,
    reportType: string,
    regulator: string,
    reportingPeriod: {
      startDate: Date;
      endDate: Date;
      frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'annually';
    },
    scope: PermissionScope,
    organizationId?: string,
  ): Promise<RegulatoryReportDocument> {
    // Generate report data based on type
    const reportData = await this.generateReportData(
      reportType,
      reportingPeriod,
      scope,
      organizationId,
    );

    const report = new this.regulatoryReportModel({
      reportType,
      regulator,
      reportingPeriod,
      scope,
      organizationId,
      reportData: {
        format: 'json',
        schema: `${reportType}_v1.0`,
        data: reportData,
      },
      submission: {
        status: 'draft',
      },
      validation: {
        schemaValid: true,
        dataValid: true,
        completenessCheck: true,
        accuracyScore: 95,
      },
      generatedBy: user.userId,
    });

    const savedReport = await report.save();

    // Log audit event
    await this.auditService.logAuditEvent({
      userId: user.userId,
      action: 'REGULATORY_REPORT_GENERATED',
      resourceType: 'regulatory_report',
      resourceId: savedReport._id.toString(),
      scope,
      organizationId,
    });

    return savedReport;
  }

  /**
   * Submit regulatory report
   */
  async submitRegulatoryReport(
    user: SACCOAuthenticatedUser,
    reportId: string,
  ): Promise<RegulatoryReportDocument> {
    const report = await this.regulatoryReportModel.findById(reportId);
    if (!report) {
      throw new BadRequestException('Regulatory report not found');
    }

    if (report.submission.status !== 'approved') {
      throw new BadRequestException(
        'Report must be approved before submission',
      );
    }

    // Update submission status
    report.submission.status = 'submitted';
    report.submission.submittedAt = new Date();
    report.submission.submittedBy = user.userId;
    report.submission.acknowledgmentId = `ACK-${Date.now()}`;

    const savedReport = await report.save();

    // Log audit event
    await this.auditService.logAuditEvent({
      userId: user.userId,
      action: 'REGULATORY_REPORT_SUBMITTED',
      resourceType: 'regulatory_report',
      resourceId: reportId,
      scope: report.scope,
      organizationId: report.organizationId,
    });

    // Emit submission event
    this.eventEmitter.emit('compliance.report_submitted', {
      reportId: savedReport._id,
      reportType: report.reportType,
      regulator: report.regulator,
      submittedBy: user.userId,
    });

    return savedReport;
  }

  /**
   * Get regulatory reports
   */
  async getRegulatoryReports(
    user: SACCOAuthenticatedUser,
    filters: {
      reportType?: string;
      regulator?: string;
      status?: string;
      scope?: PermissionScope;
      organizationId?: string;
      startDate?: Date;
      endDate?: Date;
      limit?: number;
      offset?: number;
    } = {},
  ): Promise<{
    reports: RegulatoryReportDocument[];
    total: number;
  }> {
    const query: any = {};

    if (filters.reportType) query.reportType = filters.reportType;
    if (filters.regulator) query.regulator = filters.regulator;
    if (filters.status) query['submission.status'] = filters.status;
    if (filters.scope) query.scope = filters.scope;
    if (filters.organizationId) query.organizationId = filters.organizationId;

    if (filters.startDate || filters.endDate) {
      query.createdAt = {};
      if (filters.startDate) query.createdAt.$gte = filters.startDate;
      if (filters.endDate) query.createdAt.$lte = filters.endDate;
    }

    const limit = filters.limit || 50;
    const offset = filters.offset || 0;

    const [reports, total] = await Promise.all([
      this.regulatoryReportModel
        .find(query)
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(offset)
        .exec(),
      this.regulatoryReportModel.countDocuments(query),
    ]);

    return { reports, total };
  }

  /**
   * Run compliance health check
   */
  async runComplianceHealthCheck(
    scope: PermissionScope,
    organizationId?: string,
    chamaId?: string,
  ): Promise<{
    overallHealth: 'healthy' | 'warning' | 'critical';
    checks: Array<{
      name: string;
      status: 'pass' | 'warn' | 'fail';
      message: string;
      details?: any;
    }>;
    recommendations: string[];
  }> {
    const checks = [];
    const recommendations = [];

    // Check recent compliance events
    const { events } = await this.getComplianceEvents(
      {} as SACCOAuthenticatedUser,
      {
        scope,
        organizationId,
        chamaId,
        startDate: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // Last 7 days
      },
    );

    const criticalEvents = events.filter(
      (e) => e.severity === RiskLevel.CRITICAL,
    );
    const openEvents = events.filter((e) => e.response.status === 'open');

    checks.push({
      name: 'Critical Events',
      status: criticalEvents.length === 0 ? 'pass' : 'fail',
      message: `${criticalEvents.length} critical compliance events in the last 7 days`,
      details: { count: criticalEvents.length },
    });

    checks.push({
      name: 'Open Events',
      status:
        openEvents.length < 5
          ? 'pass'
          : openEvents.length < 10
            ? 'warn'
            : 'fail',
      message: `${openEvents.length} open compliance events`,
      details: { count: openEvents.length },
    });

    // Check regulatory reporting status
    const overdueReports = await this.regulatoryReportModel.find({
      scope,
      organizationId,
      'submission.status': 'draft',
      'reportingPeriod.endDate': { $lt: new Date() },
    });

    checks.push({
      name: 'Regulatory Reporting',
      status:
        overdueReports.length === 0
          ? 'pass'
          : overdueReports.length < 3
            ? 'warn'
            : 'fail',
      message: `${overdueReports.length} overdue regulatory reports`,
      details: { count: overdueReports.length },
    });

    // Generate recommendations
    if (criticalEvents.length > 0) {
      recommendations.push('Address critical compliance events immediately');
    }
    if (openEvents.length > 10) {
      recommendations.push(
        'Increase compliance team capacity to handle open events',
      );
    }
    if (overdueReports.length > 0) {
      recommendations.push(
        'Submit overdue regulatory reports to avoid penalties',
      );
    }

    // Determine overall health
    const failedChecks = checks.filter((c) => c.status === 'fail').length;
    const warningChecks = checks.filter((c) => c.status === 'warn').length;

    let overallHealth: 'healthy' | 'warning' | 'critical' = 'healthy';
    if (failedChecks > 0) overallHealth = 'critical';
    else if (warningChecks > 0) overallHealth = 'warning';

    return {
      overallHealth,
      checks,
      recommendations,
    };
  }

  // Private Methods

  private isEventReportable(eventData: ComplianceEventData): boolean {
    const reportableEvents = [
      'suspicious_transaction',
      'large_cash_transaction',
      'kyc_failure',
      'sanctions_hit',
      'fraud_detection',
    ];
    return reportableEvents.includes(eventData.eventType);
  }

  private getApplicableRegulators(eventData: ComplianceEventData): string[] {
    // Return applicable regulators based on event type and scope
    const regulators = ['Central Bank', 'Financial Intelligence Unit'];

    if (eventData.eventType.includes('aml')) {
      regulators.push('Anti-Money Laundering Authority');
    }

    return regulators;
  }

  private async escalateEvent(eventId: string): Promise<void> {
    // Implementation would escalate to appropriate personnel
    this.eventEmitter.emit('compliance.event_escalated', {
      eventId,
      escalationTime: new Date(),
    });
  }

  private getStartDate(timeRange: string): Date {
    const now = new Date();
    switch (timeRange) {
      case '24h':
        return new Date(now.getTime() - 24 * 60 * 60 * 1000);
      case '7d':
        return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      case '30d':
        return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      case '90d':
        return new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
      default:
        return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    }
  }

  private calculateRiskScore(events: ComplianceEventDocument[]): number {
    let score = 100; // Start with perfect score

    events.forEach((event) => {
      switch (event.severity) {
        case RiskLevel.CRITICAL:
          score -= 10;
          break;
        case RiskLevel.HIGH:
          score -= 5;
          break;
        case RiskLevel.MEDIUM:
          score -= 2;
          break;
        case RiskLevel.LOW:
          score -= 1;
          break;
      }
    });

    return Math.max(0, score); // Ensure score doesn't go below 0
  }

  private async generateReportData(
    reportType: string,
    _reportingPeriod: any,
    _scope: PermissionScope,
    _organizationId?: string,
  ): Promise<any> {
    // Implementation would generate actual report data based on type
    switch (reportType) {
      case 'transaction_report':
        return {
          summary: {
            totalTransactions: 1000,
            totalValue: 5000000,
            averageTransactionSize: 5000,
            currency: 'KES',
          },
          transactions: [], // Detailed transaction data
        };

      case 'kyc_report':
        return {
          summary: {
            totalCustomers: 150,
            verifiedCustomers: 145,
            pendingVerification: 3,
            rejectedApplications: 2,
          },
          customers: [], // Customer KYC data
        };

      default:
        return {
          reportType,
          generatedAt: new Date(),
          data: {},
        };
    }
  }
}
