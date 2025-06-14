import {
  Injectable,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import {
  ServiceRole,
  Permission,
  PermissionScope,
  SACCOAuthenticatedUser,
} from '../common';

/**
 * System Configuration Schema
 * SYSTEM-ADMIN controlled service integrations and settings
 */
export interface SystemConfiguration {
  id: string;
  category: 'integration' | 'security' | 'compliance' | 'feature' | 'limits';
  key: string;
  value: any;
  description: string;
  scope: 'global' | 'organization' | 'chama';
  isActive: boolean;
  requiredRole: ServiceRole;
  lastModifiedBy: string;
  lastModifiedAt: Date;
  version: number;
}

/**
 * Service Integration Configuration
 */
export interface ServiceIntegration {
  id: string;
  serviceName: string;
  serviceType:
    | 'payment'
    | 'sms'
    | 'email'
    | 'banking'
    | 'blockchain'
    | 'analytics';
  provider: string;
  configuration: {
    apiUrl?: string;
    apiKey?: string;
    webhookUrl?: string;
    credentials?: Record<string, any>;
    features?: string[];
    limits?: Record<string, number>;
  };
  scope: PermissionScope[];
  isEnabled: boolean;
  healthStatus: 'healthy' | 'degraded' | 'down' | 'maintenance';
  lastHealthCheck: Date;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Telemetry and Metrics Configuration
 */
export interface TelemetryConfig {
  id: string;
  level: 'server' | 'service' | 'organization' | 'chama' | 'user';
  metricsEnabled: boolean;
  loggingLevel: 'debug' | 'info' | 'warn' | 'error';
  retentionPeriod: number; // in days
  exportTargets: {
    prometheus?: boolean;
    elasticsearch?: boolean;
    cloudWatch?: boolean;
    customEndpoint?: string;
  };
  alerting: {
    enabled: boolean;
    channels: ('email' | 'sms' | 'webhook' | 'slack')[];
    thresholds: Record<string, number>;
  };
  sampling: {
    rate: number; // 0-100 percentage
    rules: Array<{
      condition: string;
      rate: number;
    }>;
  };
}

/**
 * System Governance Service
 * Manages configuration, telemetry, and system health
 */
@Injectable()
export class GovernanceService {
  private systemConfig: Map<string, SystemConfiguration> = new Map();
  private serviceIntegrations: Map<string, ServiceIntegration> = new Map();
  private telemetryConfigs: Map<string, TelemetryConfig> = new Map();

  constructor() {
    this.initializeDefaultConfiguration();
  }

  // System Configuration Management

  /**
   * Get system configuration (SYSTEM-ADMIN only)
   */
  async getSystemConfiguration(
    user: SACCOAuthenticatedUser,
    category?: string,
  ): Promise<SystemConfiguration[]> {
    this.validateSystemAdminAccess(user);

    const configs = Array.from(this.systemConfig.values());
    return category
      ? configs.filter((config) => config.category === category)
      : configs;
  }

  /**
   * Update system configuration (SYSTEM-ADMIN only)
   */
  async updateSystemConfiguration(
    user: SACCOAuthenticatedUser,
    key: string,
    value: any,
    description?: string,
  ): Promise<SystemConfiguration> {
    this.validateSystemAdminAccess(user);

    const existing = this.systemConfig.get(key);
    if (!existing) {
      throw new BadRequestException(`Configuration key '${key}' not found`);
    }

    const updated: SystemConfiguration = {
      ...existing,
      value,
      description: description || existing.description,
      lastModifiedBy: user.userId,
      lastModifiedAt: new Date(),
      version: existing.version + 1,
    };

    this.systemConfig.set(key, updated);

    // Emit configuration change event
    await this.emitConfigurationChange(key, updated);

    return updated;
  }

  /**
   * Create new system configuration (SYSTEM-ADMIN only)
   */
  async createSystemConfiguration(
    user: SACCOAuthenticatedUser,
    config: Omit<
      SystemConfiguration,
      'id' | 'lastModifiedBy' | 'lastModifiedAt' | 'version'
    >,
  ): Promise<SystemConfiguration> {
    this.validateSystemAdminAccess(user);

    const newConfig: SystemConfiguration = {
      ...config,
      id: this.generateId(),
      lastModifiedBy: user.userId,
      lastModifiedAt: new Date(),
      version: 1,
    };

    this.systemConfig.set(config.key, newConfig);
    return newConfig;
  }

  // Service Integration Management

  /**
   * Register service integration (SYSTEM-ADMIN only)
   */
  async registerServiceIntegration(
    user: SACCOAuthenticatedUser,
    integration: Omit<
      ServiceIntegration,
      | 'id'
      | 'createdBy'
      | 'createdAt'
      | 'updatedAt'
      | 'healthStatus'
      | 'lastHealthCheck'
    >,
  ): Promise<ServiceIntegration> {
    this.validateSystemAdminAccess(user);

    const newIntegration: ServiceIntegration = {
      ...integration,
      id: this.generateId(),
      healthStatus: 'healthy',
      lastHealthCheck: new Date(),
      createdBy: user.userId,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.serviceIntegrations.set(integration.serviceName, newIntegration);

    // Initialize health monitoring
    await this.initializeHealthMonitoring(newIntegration);

    return newIntegration;
  }

  /**
   * Get service integrations
   */
  async getServiceIntegrations(
    user: SACCOAuthenticatedUser,
    serviceType?: string,
  ): Promise<ServiceIntegration[]> {
    // ADMIN users can view service integrations
    if (
      user.serviceRole !== ServiceRole.SYSTEM_ADMIN &&
      user.serviceRole !== ServiceRole.ADMIN
    ) {
      throw new ForbiddenException(
        'Insufficient permissions to view service integrations',
      );
    }

    const integrations = Array.from(this.serviceIntegrations.values());

    // Filter sensitive information for non-system admins
    if (user.serviceRole !== ServiceRole.SYSTEM_ADMIN) {
      integrations.forEach((integration) => {
        delete integration.configuration.credentials;
        delete integration.configuration.apiKey;
      });
    }

    return serviceType
      ? integrations.filter(
          (integration) => integration.serviceType === serviceType,
        )
      : integrations;
  }

  /**
   * Update service integration status
   */
  async updateServiceIntegrationStatus(
    user: SACCOAuthenticatedUser,
    serviceName: string,
    isEnabled: boolean,
  ): Promise<ServiceIntegration> {
    this.validateSystemAdminAccess(user);

    const integration = this.serviceIntegrations.get(serviceName);
    if (!integration) {
      throw new BadRequestException(
        `Service integration '${serviceName}' not found`,
      );
    }

    integration.isEnabled = isEnabled;
    integration.updatedAt = new Date();

    this.serviceIntegrations.set(serviceName, integration);
    return integration;
  }

  // Telemetry and Monitoring Configuration

  /**
   * Configure telemetry settings (SYSTEM-ADMIN only)
   */
  async configureTelemetry(
    user: SACCOAuthenticatedUser,
    level: TelemetryConfig['level'],
    config: Omit<TelemetryConfig, 'id' | 'level'>,
  ): Promise<TelemetryConfig> {
    this.validateSystemAdminAccess(user);

    const telemetryConfig: TelemetryConfig = {
      ...config,
      id: this.generateId(),
      level,
    };

    this.telemetryConfigs.set(level, telemetryConfig);

    // Apply configuration changes
    await this.applyTelemetryConfiguration(telemetryConfig);

    return telemetryConfig;
  }

  /**
   * Get telemetry configuration
   */
  async getTelemetryConfiguration(
    user: SACCOAuthenticatedUser,
    level?: TelemetryConfig['level'],
  ): Promise<TelemetryConfig[]> {
    // ADMIN users can view telemetry configuration
    if (
      user.serviceRole !== ServiceRole.SYSTEM_ADMIN &&
      user.serviceRole !== ServiceRole.ADMIN
    ) {
      throw new ForbiddenException(
        'Insufficient permissions to view telemetry configuration',
      );
    }

    const configs = Array.from(this.telemetryConfigs.values());
    return level ? configs.filter((config) => config.level === level) : configs;
  }

  // Health Monitoring and Observability

  /**
   * Get system health status
   */
  async getSystemHealth(user: SACCOAuthenticatedUser): Promise<{
    overall: 'healthy' | 'degraded' | 'down';
    server: any;
    services: any[];
    integrations: any[];
    lastChecked: Date;
  }> {
    // ADMIN and SYSTEM_ADMIN can view system health
    if (
      user.serviceRole !== ServiceRole.SYSTEM_ADMIN &&
      user.serviceRole !== ServiceRole.ADMIN
    ) {
      throw new ForbiddenException(
        'Insufficient permissions to view system health',
      );
    }

    const serviceHealths = await this.checkAllServiceHealth();
    const integrationHealths = await this.checkIntegrationHealth();

    const overall = this.calculateOverallHealth([
      ...serviceHealths,
      ...integrationHealths,
    ]);

    return {
      overall,
      server: await this.getServerHealth(),
      services: serviceHealths,
      integrations: integrationHealths,
      lastChecked: new Date(),
    };
  }

  /**
   * Get organization-level metrics (scope-aware)
   */
  async getOrganizationMetrics(
    user: SACCOAuthenticatedUser,
    organizationId: string,
    timeRange: '1h' | '24h' | '7d' | '30d' = '24h',
  ): Promise<{
    members: any;
    financial: any;
    activity: any;
    compliance: any;
  }> {
    // Validate user has access to organization metrics
    const hasPermission = user.groupMemberships?.some(
      (membership) =>
        membership.groupId === organizationId &&
        membership.groupType === 'organization' &&
        membership.permissions.includes(Permission.REPORTS_READ),
    );

    if (!hasPermission && user.serviceRole !== ServiceRole.SYSTEM_ADMIN) {
      throw new ForbiddenException(
        'Insufficient permissions to view organization metrics',
      );
    }

    return {
      members: await this.getOrganizationMemberMetrics(
        organizationId,
        timeRange,
      ),
      financial: await this.getOrganizationFinancialMetrics(
        organizationId,
        timeRange,
      ),
      activity: await this.getOrganizationActivityMetrics(
        organizationId,
        timeRange,
      ),
      compliance: await this.getOrganizationComplianceMetrics(
        organizationId,
        timeRange,
      ),
    };
  }

  /**
   * Get chama-level metrics (scope-aware)
   */
  async getChamaMetrics(
    user: SACCOAuthenticatedUser,
    chamaId: string,
    timeRange: '1h' | '24h' | '7d' | '30d' = '24h',
  ): Promise<{
    members: any;
    contributions: any;
    loans: any;
    activity: any;
  }> {
    // Validate user has access to chama metrics
    const hasPermission = user.groupMemberships?.some(
      (membership) =>
        membership.groupId === chamaId &&
        membership.groupType === 'chama' &&
        membership.permissions.includes(Permission.REPORTS_READ),
    );

    if (!hasPermission && user.serviceRole !== ServiceRole.SYSTEM_ADMIN) {
      throw new ForbiddenException(
        'Insufficient permissions to view chama metrics',
      );
    }

    return {
      members: await this.getChamaMemberMetrics(chamaId, timeRange),
      contributions: await this.getChamaContributionMetrics(chamaId, timeRange),
      loans: await this.getChamaLoanMetrics(chamaId, timeRange),
      activity: await this.getChamaActivityMetrics(chamaId, timeRange),
    };
  }

  // Alert and Notification Management

  /**
   * Configure alerts (SYSTEM-ADMIN only)
   */
  async configureAlerts(
    user: SACCOAuthenticatedUser,
    _alertConfig: {
      type: 'system' | 'service' | 'organization' | 'chama';
      conditions: Array<{
        metric: string;
        operator: '>' | '<' | '>=' | '<=' | '==' | '!=';
        threshold: number;
        duration: number; // in minutes
      }>;
      actions: Array<{
        type: 'email' | 'sms' | 'webhook' | 'slack';
        recipients: string[];
        template?: string;
        webhook?: string;
      }>;
      isEnabled: boolean;
    },
  ): Promise<any> {
    this.validateSystemAdminAccess(user);

    // Implementation would store alert configuration
    // and set up monitoring triggers
    return { success: true, alertId: this.generateId() };
  }

  // Private Methods

  private validateSystemAdminAccess(user: SACCOAuthenticatedUser): void {
    if (user.serviceRole !== ServiceRole.SYSTEM_ADMIN) {
      throw new ForbiddenException('SYSTEM_ADMIN role required');
    }
  }

  private initializeDefaultConfiguration(): void {
    // Default system configurations
    const defaultConfigs: SystemConfiguration[] = [
      {
        id: 'sys-001',
        category: 'security',
        key: 'jwt.expiration',
        value: '24h',
        description: 'JWT token expiration time',
        scope: 'global',
        isActive: true,
        requiredRole: ServiceRole.SYSTEM_ADMIN,
        lastModifiedBy: 'system',
        lastModifiedAt: new Date(),
        version: 1,
      },
      {
        id: 'sys-002',
        category: 'limits',
        key: 'api.rate_limit.requests_per_minute',
        value: 60,
        description: 'API rate limit per minute per user',
        scope: 'global',
        isActive: true,
        requiredRole: ServiceRole.SYSTEM_ADMIN,
        lastModifiedBy: 'system',
        lastModifiedAt: new Date(),
        version: 1,
      },
      {
        id: 'sys-003',
        category: 'compliance',
        key: 'data_retention.transaction_logs',
        value: 2555, // 7 years in days
        description: 'Transaction log retention period in days',
        scope: 'global',
        isActive: true,
        requiredRole: ServiceRole.SYSTEM_ADMIN,
        lastModifiedBy: 'system',
        lastModifiedAt: new Date(),
        version: 1,
      },
    ];

    defaultConfigs.forEach((config) => {
      this.systemConfig.set(config.key, config);
    });
  }

  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private async emitConfigurationChange(
    key: string,
    config: SystemConfiguration,
  ): Promise<void> {
    // Implementation would emit events for configuration changes
    console.log(`Configuration changed: ${key}`, config);
  }

  private async initializeHealthMonitoring(
    integration: ServiceIntegration,
  ): Promise<void> {
    // Implementation would set up health check monitoring
    console.log(
      `Health monitoring initialized for: ${integration.serviceName}`,
    );
  }

  private async applyTelemetryConfiguration(
    config: TelemetryConfig,
  ): Promise<void> {
    // Implementation would apply telemetry configuration
    console.log(`Telemetry configuration applied for level: ${config.level}`);
  }

  private async checkAllServiceHealth(): Promise<any[]> {
    // Implementation would check health of all services
    return [
      { service: 'database', status: 'healthy', responseTime: 15 },
      { service: 'redis', status: 'healthy', responseTime: 5 },
      { service: 'auth', status: 'healthy', responseTime: 25 },
    ];
  }

  private async checkIntegrationHealth(): Promise<any[]> {
    // Implementation would check health of all integrations
    return Array.from(this.serviceIntegrations.values()).map((integration) => ({
      service: integration.serviceName,
      status: integration.healthStatus,
      lastCheck: integration.lastHealthCheck,
    }));
  }

  private calculateOverallHealth(
    healthChecks: any[],
  ): 'healthy' | 'degraded' | 'down' {
    const unhealthyCount = healthChecks.filter(
      (check) => check.status === 'down' || check.status === 'degraded',
    ).length;

    if (unhealthyCount === 0) return 'healthy';
    if (unhealthyCount < healthChecks.length / 2) return 'degraded';
    return 'down';
  }

  private async getServerHealth(): Promise<any> {
    // Implementation would return server health metrics
    return {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      version: process.version,
    };
  }

  private async getOrganizationMemberMetrics(
    organizationId: string,
    timeRange: string,
  ): Promise<any> {
    // Implementation would return organization member metrics
    return {
      totalMembers: 150,
      activeMembers: 145,
      newMembers: 5,
      memberGrowthRate: 3.4,
      timeRange,
    };
  }

  private async getOrganizationFinancialMetrics(
    organizationId: string,
    timeRange: string,
  ): Promise<any> {
    // Implementation would return organization financial metrics
    return {
      totalDeposits: 1500000,
      totalWithdrawals: 800000,
      netBalance: 700000,
      transactionCount: 342,
      averageTransactionSize: 4386,
      timeRange,
    };
  }

  private async getOrganizationActivityMetrics(
    organizationId: string,
    timeRange: string,
  ): Promise<any> {
    // Implementation would return organization activity metrics
    return {
      apiCalls: 5420,
      uniqueUsers: 89,
      errorRate: 0.5,
      averageResponseTime: 145,
      timeRange,
    };
  }

  private async getOrganizationComplianceMetrics(
    organizationId: string,
    timeRange: string,
  ): Promise<any> {
    // Implementation would return compliance metrics
    return {
      kycCompliance: 98.5,
      transactionLimitsCompliance: 100,
      auditTrailCompliance: 100,
      regulatoryReports: 12,
      timeRange,
    };
  }

  private async getChamaMemberMetrics(
    chamaId: string,
    timeRange: string,
  ): Promise<any> {
    // Implementation would return chama member metrics
    return {
      totalMembers: 25,
      activeMembers: 23,
      meetingAttendance: 85.5,
      timeRange,
    };
  }

  private async getChamaContributionMetrics(
    chamaId: string,
    timeRange: string,
  ): Promise<any> {
    // Implementation would return chama contribution metrics
    return {
      totalContributions: 125000,
      averageContribution: 5000,
      contributionCompliance: 92.3,
      latePayments: 2,
      timeRange,
    };
  }

  private async getChamaLoanMetrics(
    chamaId: string,
    timeRange: string,
  ): Promise<any> {
    // Implementation would return chama loan metrics
    return {
      loansIssued: 8,
      totalLoanAmount: 80000,
      repaymentRate: 95.2,
      defaultRate: 4.8,
      timeRange,
    };
  }

  private async getChamaActivityMetrics(
    chamaId: string,
    timeRange: string,
  ): Promise<any> {
    // Implementation would return chama activity metrics
    return {
      meetingsHeld: 4,
      transactionCount: 156,
      memberEngagement: 78.5,
      timeRange,
    };
  }
}
