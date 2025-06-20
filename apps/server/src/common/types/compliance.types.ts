export enum RiskLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export interface ComplianceContext {
  memberId: string;
  organizationId?: string;
  chamaId?: string;
  scope: string;
  timestamp: Date;
  correlationId?: string;
}

// IComplianceLogger interface removed - ComplianceService used directly
