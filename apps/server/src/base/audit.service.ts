import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { AuditTrail, AuditTrailDocument, PermissionScope } from '../common';

export interface AuditEventData {
  userId: string;
  impersonatedBy?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  scope: PermissionScope;
  organizationId?: string;
  chamaId?: string;
  requestData?: {
    method: string;
    endpoint: string;
    parameters?: Record<string, any>;
    body?: any;
    userAgent: string;
    ipAddress: string;
    sessionId?: string;
  };
  responseData?: {
    statusCode: number;
    success: boolean;
    error?: string;
    changes?: Array<{
      field: string;
      oldValue: any;
      newValue: any;
    }>;
  };
  complianceContext?: {
    workflowId?: string;
    approvalRequired: boolean;
    approvalStatus?: string;
    riskLevel?: string;
    sensitiveData: boolean;
    dataClassification?: 'public' | 'internal' | 'confidential' | 'restricted';
  };
  businessContext?: {
    amount?: number;
    currency?: string;
    transactionType?: string;
    counterparty?: string;
    businessJustification?: string;
  };
  tags?: string[];
}

export interface AuditQueryFilters {
  userId?: string;
  action?: string;
  resourceType?: string;
  scope?: PermissionScope;
  organizationId?: string;
  chamaId?: string;
  startDate?: Date;
  endDate?: Date;
  sensitiveData?: boolean;
  riskLevel?: string;
  limit?: number;
  offset?: number;
}

/**
 * Enhanced Audit Service for Compliance
 * Provides comprehensive audit logging and trail management
 */
@Injectable()
export class AuditService {
  constructor(
    @InjectModel(AuditTrail.name)
    private auditTrailModel: Model<AuditTrailDocument>,
  ) {}

  /**
   * Log an audit event
   */
  async logAuditEvent(eventData: AuditEventData): Promise<AuditTrailDocument> {
    const auditEvent = new this.auditTrailModel({
      eventId: this.generateEventId(),
      ...eventData,
      complianceContext: {
        approvalRequired: false,
        sensitiveData: false,
        dataClassification: 'internal',
        ...eventData.complianceContext,
      },
      tags: eventData.tags || [],
      isArchived: false,
      retentionDate: this.calculateRetentionDate(eventData),
    });

    return auditEvent.save();
  }

  /**
   * Get audit logs with filtering and pagination
   */
  async getAuditLogs(filters: AuditQueryFilters = {}): Promise<{
    logs: AuditTrailDocument[];
    total: number;
    limit: number;
    offset: number;
  }> {
    const query: any = { isArchived: false };

    // Apply filters
    if (filters.userId) query.userId = filters.userId;
    if (filters.action)
      query.action = { $regex: filters.action, $options: 'i' };
    if (filters.resourceType) query.resourceType = filters.resourceType;
    if (filters.scope) query.scope = filters.scope;
    if (filters.organizationId) query.organizationId = filters.organizationId;
    if (filters.chamaId) query.chamaId = filters.chamaId;
    if (filters.sensitiveData !== undefined) {
      query['complianceContext.sensitiveData'] = filters.sensitiveData;
    }
    if (filters.riskLevel) {
      query['complianceContext.riskLevel'] = filters.riskLevel;
    }

    // Date range filter
    if (filters.startDate || filters.endDate) {
      query.createdAt = {};
      if (filters.startDate) query.createdAt.$gte = filters.startDate;
      if (filters.endDate) query.createdAt.$lte = filters.endDate;
    }

    const limit = filters.limit || 100;
    const offset = filters.offset || 0;

    const [logs, total] = await Promise.all([
      this.auditTrailModel
        .find(query)
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(offset)
        .exec(),
      this.auditTrailModel.countDocuments(query),
    ]);

    return { logs, total, limit, offset };
  }

  /**
   * Get audit trail for a specific resource
   */
  async getResourceAuditTrail(
    resourceType: string,
    resourceId: string,
    scope?: PermissionScope,
  ): Promise<AuditTrailDocument[]> {
    const query: any = {
      resourceType,
      resourceId,
      isArchived: false,
    };

    if (scope) query.scope = scope;

    return this.auditTrailModel.find(query).sort({ createdAt: -1 }).exec();
  }

  /**
   * Get user activity audit trail
   */
  async getUserAuditTrail(
    userId: string,
    startDate?: Date,
    endDate?: Date,
    limit: number = 100,
  ): Promise<AuditTrailDocument[]> {
    const query: any = {
      userId,
      isArchived: false,
    };

    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = startDate;
      if (endDate) query.createdAt.$lte = endDate;
    }

    return this.auditTrailModel
      .find(query)
      .sort({ createdAt: -1 })
      .limit(limit)
      .exec();
  }

  /**
   * Get audit statistics and analytics
   */
  async getAuditStatistics(
    scope?: PermissionScope,
    organizationId?: string,
    chamaId?: string,
    days: number = 30,
  ): Promise<{
    totalEvents: number;
    uniqueUsers: number;
    topActions: Array<{ action: string; count: number }>;
    riskDistribution: Record<string, number>;
    sensitiveDataAccess: number;
    failedOperations: number;
    timelineData: Array<{ date: string; count: number }>;
  }> {
    const endDate = new Date();
    const startDate = new Date(endDate.getTime() - days * 24 * 60 * 60 * 1000);

    const query: any = {
      createdAt: { $gte: startDate, $lte: endDate },
      isArchived: false,
    };

    if (scope) query.scope = scope;
    if (organizationId) query.organizationId = organizationId;
    if (chamaId) query.chamaId = chamaId;

    // Get basic statistics
    const [totalEvents, logs] = await Promise.all([
      this.auditTrailModel.countDocuments(query),
      this.auditTrailModel.find(query).exec(),
    ]);

    // Calculate unique users
    const uniqueUsers = new Set(logs.map((log) => log.userId)).size;

    // Calculate top actions
    const actionCounts = logs.reduce(
      (acc, log) => {
        acc[log.action] = (acc[log.action] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>,
    );

    const topActions = Object.entries(actionCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([action, count]) => ({ action, count }));

    // Calculate risk distribution
    const riskDistribution = logs.reduce(
      (acc, log) => {
        const risk = log.complianceContext?.riskLevel || 'unknown';
        acc[risk] = (acc[risk] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>,
    );

    // Count sensitive data access
    const sensitiveDataAccess = logs.filter(
      (log) => log.complianceContext?.sensitiveData,
    ).length;

    // Count failed operations
    const failedOperations = logs.filter(
      (log) => log.responseData?.success === false,
    ).length;

    // Generate timeline data (daily aggregation)
    const timelineData = this.generateTimelineData(logs, startDate, endDate);

    return {
      totalEvents,
      uniqueUsers,
      topActions,
      riskDistribution,
      sensitiveDataAccess,
      failedOperations,
      timelineData,
    };
  }

  /**
   * Search audit logs with advanced criteria
   */
  async searchAuditLogs(searchCriteria: {
    keyword?: string;
    userId?: string;
    ipAddress?: string;
    userAgent?: string;
    amountRange?: { min: number; max: number };
    riskLevels?: string[];
    dataClassifications?: string[];
    scope?: PermissionScope;
    organizationId?: string;
    chamaId?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
    offset?: number;
  }): Promise<{
    logs: AuditTrailDocument[];
    total: number;
    searchQuery: string;
  }> {
    const query: any = { isArchived: false };

    // Keyword search across action and resource type
    if (searchCriteria.keyword) {
      query.$or = [
        { action: { $regex: searchCriteria.keyword, $options: 'i' } },
        { resourceType: { $regex: searchCriteria.keyword, $options: 'i' } },
        {
          'businessContext.businessJustification': {
            $regex: searchCriteria.keyword,
            $options: 'i',
          },
        },
      ];
    }

    // User and session filters
    if (searchCriteria.userId) query.userId = searchCriteria.userId;
    if (searchCriteria.ipAddress) {
      query['requestData.ipAddress'] = searchCriteria.ipAddress;
    }
    if (searchCriteria.userAgent) {
      query['requestData.userAgent'] = {
        $regex: searchCriteria.userAgent,
        $options: 'i',
      };
    }

    // Amount range filter
    if (searchCriteria.amountRange) {
      query['businessContext.amount'] = {
        $gte: searchCriteria.amountRange.min,
        $lte: searchCriteria.amountRange.max,
      };
    }

    // Risk and classification filters
    if (searchCriteria.riskLevels && searchCriteria.riskLevels.length > 0) {
      query['complianceContext.riskLevel'] = { $in: searchCriteria.riskLevels };
    }
    if (
      searchCriteria.dataClassifications &&
      searchCriteria.dataClassifications.length > 0
    ) {
      query['complianceContext.dataClassification'] = {
        $in: searchCriteria.dataClassifications,
      };
    }

    // Scope filters
    if (searchCriteria.scope) query.scope = searchCriteria.scope;
    if (searchCriteria.organizationId)
      query.organizationId = searchCriteria.organizationId;
    if (searchCriteria.chamaId) query.chamaId = searchCriteria.chamaId;

    // Date range
    if (searchCriteria.startDate || searchCriteria.endDate) {
      query.createdAt = {};
      if (searchCriteria.startDate)
        query.createdAt.$gte = searchCriteria.startDate;
      if (searchCriteria.endDate) query.createdAt.$lte = searchCriteria.endDate;
    }

    const limit = searchCriteria.limit || 100;
    const offset = searchCriteria.offset || 0;

    const [logs, total] = await Promise.all([
      this.auditTrailModel
        .find(query)
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(offset)
        .exec(),
      this.auditTrailModel.countDocuments(query),
    ]);

    return {
      logs,
      total,
      searchQuery: JSON.stringify(query),
    };
  }

  /**
   * Export audit logs for compliance reporting
   */
  async exportAuditLogs(
    filters: AuditQueryFilters,
    format: 'json' | 'csv' | 'pdf' = 'json',
  ): Promise<{
    data: any;
    filename: string;
    mimeType: string;
  }> {
    const { logs } = await this.getAuditLogs({ ...filters, limit: 10000 });

    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `audit_logs_${timestamp}.${format}`;

    switch (format) {
      case 'csv':
        return {
          data: this.convertToCSV(logs),
          filename,
          mimeType: 'text/csv',
        };

      case 'pdf':
        return {
          data: await this.generatePDFReport(logs),
          filename,
          mimeType: 'application/pdf',
        };

      default:
        return {
          data: {
            exportedAt: new Date(),
            totalRecords: logs.length,
            filters,
            logs: logs.map((log) => log.toObject()),
          },
          filename,
          mimeType: 'application/json',
        };
    }
  }

  /**
   * Archive old audit logs based on retention policy
   */
  async archiveOldLogs(): Promise<{
    archivedCount: number;
    deletedCount: number;
  }> {
    const now = new Date();

    // Find logs that should be archived (older than retention date)
    const _logsToArchive = await this.auditTrailModel.find({
      retentionDate: { $lt: now },
      isArchived: false,
    });

    // Archive logs (mark as archived, don't delete immediately)
    const archiveResult = await this.auditTrailModel.updateMany(
      {
        retentionDate: { $lt: now },
        isArchived: false,
      },
      {
        isArchived: true,
      },
    );

    // Delete very old archived logs (e.g., 2 years after archiving)
    const deleteThreshold = new Date(
      now.getTime() - 2 * 365 * 24 * 60 * 60 * 1000,
    );
    const deleteResult = await this.auditTrailModel.deleteMany({
      isArchived: true,
      updatedAt: { $lt: deleteThreshold },
    });

    return {
      archivedCount: archiveResult.modifiedCount,
      deletedCount: deleteResult.deletedCount || 0,
    };
  }

  /**
   * Get compliance-ready audit report
   */
  async getComplianceAuditReport(
    scope: PermissionScope,
    organizationId?: string,
    startDate?: Date,
    endDate?: Date,
  ): Promise<{
    summary: {
      totalEvents: number;
      sensitiveDataAccess: number;
      highRiskOperations: number;
      failedLogins: number;
      privilegedOperations: number;
    };
    details: {
      userActivity: Array<{
        userId: string;
        eventCount: number;
        lastActivity: Date;
      }>;
      resourceAccess: Array<{
        resourceType: string;
        accessCount: number;
        lastAccess: Date;
      }>;
      riskEvents: AuditTrailDocument[];
      failedOperations: AuditTrailDocument[];
    };
  }> {
    const query: any = { scope, isArchived: false };
    if (organizationId) query.organizationId = organizationId;
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = startDate;
      if (endDate) query.createdAt.$lte = endDate;
    }

    const logs = await this.auditTrailModel.find(query).exec();

    // Calculate summary metrics
    const summary = {
      totalEvents: logs.length,
      sensitiveDataAccess: logs.filter(
        (log) => log.complianceContext?.sensitiveData,
      ).length,
      highRiskOperations: logs.filter(
        (log) =>
          log.complianceContext?.riskLevel === 'high' ||
          log.complianceContext?.riskLevel === 'critical',
      ).length,
      failedLogins: logs.filter(
        (log) =>
          log.action === 'USER_LOGIN' && log.responseData?.success === false,
      ).length,
      privilegedOperations: logs.filter(
        (log) =>
          log.complianceContext?.dataClassification === 'restricted' ||
          log.complianceContext?.dataClassification === 'confidential',
      ).length,
    };

    // Generate detailed analysis
    const userActivityMap = logs.reduce(
      (acc, log) => {
        if (!acc[log.userId]) {
          acc[log.userId] = { eventCount: 0, lastActivity: log.createdAt };
        }
        acc[log.userId].eventCount++;
        if (log.createdAt > acc[log.userId].lastActivity) {
          acc[log.userId].lastActivity = log.createdAt;
        }
        return acc;
      },
      {} as Record<string, { eventCount: number; lastActivity: Date }>,
    );

    const userActivity = Object.entries(userActivityMap)
      .map(([userId, data]) => ({ userId, ...data }))
      .sort((a, b) => b.eventCount - a.eventCount);

    const resourceAccessMap = logs.reduce(
      (acc, log) => {
        const key = log.resourceType;
        if (!acc[key]) {
          acc[key] = { accessCount: 0, lastAccess: log.createdAt };
        }
        acc[key].accessCount++;
        if (log.createdAt > acc[key].lastAccess) {
          acc[key].lastAccess = log.createdAt;
        }
        return acc;
      },
      {} as Record<string, { accessCount: number; lastAccess: Date }>,
    );

    const resourceAccess = Object.entries(resourceAccessMap)
      .map(([resourceType, data]) => ({ resourceType, ...data }))
      .sort((a, b) => b.accessCount - a.accessCount);

    const riskEvents = logs
      .filter(
        (log) =>
          log.complianceContext?.riskLevel === 'high' ||
          log.complianceContext?.riskLevel === 'critical',
      )
      .slice(0, 50);

    const failedOperations = logs
      .filter((log) => log.responseData?.success === false)
      .slice(0, 50);

    return {
      summary,
      details: {
        userActivity,
        resourceAccess,
        riskEvents,
        failedOperations,
      },
    };
  }

  // Private Methods

  private generateEventId(): string {
    return `audit-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private calculateRetentionDate(eventData: AuditEventData): Date {
    // Default retention: 7 years for financial records
    const retentionYears = 7;

    // Extend retention for sensitive data
    if (eventData.complianceContext?.sensitiveData) {
      return new Date(
        Date.now() + (retentionYears + 3) * 365 * 24 * 60 * 60 * 1000,
      );
    }

    return new Date(Date.now() + retentionYears * 365 * 24 * 60 * 60 * 1000);
  }

  private generateTimelineData(
    logs: AuditTrailDocument[],
    startDate: Date,
    endDate: Date,
  ): Array<{ date: string; count: number }> {
    const timelineMap = new Map<string, number>();

    // Initialize all dates in range with 0
    const currentDate = new Date(startDate);
    while (currentDate <= endDate) {
      const dateStr = currentDate.toISOString().split('T')[0];
      timelineMap.set(dateStr, 0);
      currentDate.setDate(currentDate.getDate() + 1);
    }

    // Count events by date
    logs.forEach((log) => {
      const dateStr = log.createdAt.toISOString().split('T')[0];
      timelineMap.set(dateStr, (timelineMap.get(dateStr) || 0) + 1);
    });

    return Array.from(timelineMap.entries())
      .map(([date, count]) => ({ date, count }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }

  private convertToCSV(logs: AuditTrailDocument[]): string {
    const headers = [
      'Timestamp',
      'User ID',
      'Action',
      'Resource Type',
      'Resource ID',
      'Scope',
      'Organization ID',
      'Chama ID',
      'Success',
      'Risk Level',
      'Sensitive Data',
      'IP Address',
      'User Agent',
    ];

    const rows = logs.map((log) => [
      log.createdAt.toISOString(),
      log.userId,
      log.action,
      log.resourceType,
      log.resourceId || '',
      log.scope,
      log.organizationId || '',
      log.chamaId || '',
      log.responseData?.success?.toString() || '',
      log.complianceContext?.riskLevel || '',
      log.complianceContext?.sensitiveData?.toString() || '',
      log.requestData?.ipAddress || '',
      log.requestData?.userAgent || '',
    ]);

    return [headers, ...rows]
      .map((row) => row.map((cell) => `"${cell}"`).join(','))
      .join('\n');
  }

  private async generatePDFReport(
    _logs: AuditTrailDocument[],
  ): Promise<Buffer> {
    // Implementation would use a PDF library to generate the report
    // For now, return a mock buffer
    return Buffer.from('PDF report would be generated here');
  }
}
