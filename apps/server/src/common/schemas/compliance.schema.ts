import { Document } from 'mongoose';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import {
  ServiceRole,
  GroupRole,
  Permission,
  PermissionScope,
} from '../sacco-types';

/**
 * Maker-Checker Workflow Schema
 * Implements dual control and approval mechanisms for financial operations
 */

export enum ApprovalStatus {
  PENDING = 'pending',
  APPROVED = 'approved',
  REJECTED = 'rejected',
  EXPIRED = 'expired',
  CANCELLED = 'cancelled',
}

export enum WorkflowType {
  FINANCIAL_TRANSACTION = 'financial_transaction',
  USER_MANAGEMENT = 'user_management',
  CONFIGURATION_CHANGE = 'configuration_change',
  LOAN_APPROVAL = 'loan_approval',
  SHARES_ISSUANCE = 'shares_issuance',
  MEMBER_ONBOARDING = 'member_onboarding',
  ACCOUNT_CLOSURE = 'account_closure',
  LIMIT_OVERRIDE = 'limit_override',
  SYSTEM_MAINTENANCE = 'system_maintenance',
}

export enum RiskLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

@Schema({ timestamps: true })
export class ApprovalWorkflow {
  @Prop({ required: true, type: String, enum: WorkflowType })
  workflowType: WorkflowType;

  @Prop({ required: true })
  initiatedBy: string; // Maker

  @Prop({ required: true })
  organizationId: string;

  @Prop()
  chamaId?: string;

  @Prop({ required: true, type: String, enum: PermissionScope })
  scope: PermissionScope;

  @Prop({ required: true, type: String, enum: RiskLevel })
  riskLevel: RiskLevel;

  @Prop({
    required: true,
    type: String,
    enum: ApprovalStatus,
    default: ApprovalStatus.PENDING,
  })
  status: ApprovalStatus;

  // The actual operation data
  @Prop({ type: Object, required: true })
  operationData: {
    action: string;
    resourceType: string;
    resourceId?: string;
    parameters: Record<string, any>;
    estimatedValue?: number;
    currency?: string;
    description: string;
  };

  // Approval chain configuration
  @Prop({ type: Object, required: true })
  approvalChain: {
    requiredApprovals: number;
    requiredRoles: (ServiceRole | GroupRole)[];
    requiredPermissions: Permission[];
    allowSelfApproval: boolean;
    sequentialApproval: boolean; // true = must approve in order, false = any order
    timeoutHours: number;
  };

  // Current approval state
  @Prop([
    {
      approverId: { type: String, required: true },
      approverRole: { type: String, required: true },
      status: { type: String, enum: ApprovalStatus, required: true },
      comment: String,
      approvedAt: Date,
      ipAddress: String,
      userAgent: String,
    },
  ])
  approvals: Array<{
    approverId: string;
    approverRole: ServiceRole | GroupRole;
    status: ApprovalStatus;
    comment?: string;
    approvedAt?: Date;
    ipAddress?: string;
    userAgent?: string;
  }>;

  @Prop()
  expiresAt?: Date;

  @Prop()
  executedAt?: Date;

  @Prop()
  executedBy?: string;

  @Prop({ type: Object })
  executionResult?: {
    success: boolean;
    transactionId?: string;
    error?: string;
    rollbackId?: string;
  };

  // Compliance tracking
  @Prop({ type: Object })
  complianceChecks: {
    amlScreening?: {
      status: 'passed' | 'flagged' | 'failed';
      score?: number;
      details?: string;
    };
    sanctionsCheck?: {
      status: 'passed' | 'flagged' | 'failed';
      details?: string;
    };
    riskAssessment?: {
      score: number;
      factors: string[];
      mitigation?: string;
    };
    regulatoryRequirements?: {
      kyc: boolean;
      documentation: string[];
      approvals: string[];
    };
  };

  @Prop([String])
  tags: string[];

  @Prop({ type: Object })
  metadata: {
    sourceSystem?: string;
    correlationId?: string;
    businessJustification?: string;
    urgency?: 'low' | 'medium' | 'high' | 'critical';
    customerImpact?: 'none' | 'low' | 'medium' | 'high';
    cancellationReason?: string;
    cancelledBy?: string;
    cancelledAt?: Date;
  };
}

export type ApprovalWorkflowDocument = ApprovalWorkflow & Document;
export const ApprovalWorkflowSchema =
  SchemaFactory.createForClass(ApprovalWorkflow);

/**
 * Segregation of Duties (SoD) Rules Schema
 * Defines conflicting roles and operations that require separation
 */
@Schema({ timestamps: true })
export class SegregationRule {
  @Prop({ required: true, unique: true })
  ruleName: string;

  @Prop({ required: true })
  description: string;

  @Prop({ required: true, type: String, enum: PermissionScope })
  scope: PermissionScope;

  @Prop({ required: true })
  isActive: boolean;

  // Define conflicting operations
  @Prop({ type: Object, required: true })
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
    conflictType: 'same_user' | 'same_role' | 'same_session' | 'time_window';
    timeWindowHours?: number;
  };

  // Enforcement settings
  @Prop({ type: Object })
  enforcement: {
    blockConflicting: boolean;
    requireApproval: boolean;
    alertLevel: 'info' | 'warning' | 'critical';
    notificationChannels: ('email' | 'sms' | 'dashboard' | 'audit')[];
  };

  @Prop()
  createdBy: string;

  @Prop()
  lastModifiedBy: string;
}

export type SegregationRuleDocument = SegregationRule & Document;
export const SegregationRuleSchema =
  SchemaFactory.createForClass(SegregationRule);

/**
 * Transaction Limits Schema
 * Defines financial limits and controls
 */
@Schema({ timestamps: true })
export class TransactionLimit {
  @Prop({ required: true })
  limitName: string;

  @Prop({ required: true, type: String, enum: PermissionScope })
  scope: PermissionScope;

  @Prop()
  organizationId?: string;

  @Prop()
  chamaId?: string;

  @Prop()
  userId?: string; // For personal limits

  @Prop([{ type: String, enum: [ServiceRole, GroupRole] }])
  applicableRoles: (ServiceRole | GroupRole)[];

  @Prop({ required: true })
  currency: string;

  // Limit definitions
  @Prop({ type: Object, required: true })
  limits: {
    // Per transaction limits
    maxTransactionAmount: number;
    minTransactionAmount?: number;

    // Periodic limits
    dailyLimit?: number;
    weeklyLimit?: number;
    monthlyLimit?: number;
    yearlyLimit?: number;

    // Count limits
    dailyTransactionCount?: number;
    monthlyTransactionCount?: number;

    // Cumulative limits
    totalLifetimeLimit?: number;
    outstandingLimit?: number; // For loans
  };

  // Operations this limit applies to
  @Prop([String])
  applicableOperations: string[];

  // Override conditions
  @Prop({ type: Object })
  overrideConditions: {
    allowOverride: boolean;
    overrideRoles: (ServiceRole | GroupRole)[];
    overridePermissions: Permission[];
    requiresApproval: boolean;
    maxOverridePercentage?: number;
  };

  @Prop({ default: true })
  isActive: boolean;

  @Prop()
  effectiveFrom: Date;

  @Prop()
  effectiveUntil?: Date;

  @Prop()
  createdBy: string;
}

export type TransactionLimitDocument = TransactionLimit & Document;
export const TransactionLimitSchema =
  SchemaFactory.createForClass(TransactionLimit);

/**
 * Compliance Monitoring Schema
 * Tracks compliance violations and risk events
 */
@Schema({ timestamps: true })
export class ComplianceEvent {
  @Prop({ required: true })
  eventType: string;

  @Prop({ required: true, type: String, enum: RiskLevel })
  severity: RiskLevel;

  @Prop({ required: true, type: String, enum: PermissionScope })
  scope: PermissionScope;

  @Prop()
  organizationId?: string;

  @Prop()
  chamaId?: string;

  @Prop()
  userId?: string;

  @Prop({ required: true })
  description: string;

  @Prop({ type: Object })
  eventData: {
    transactionId?: string;
    workflowId?: string;
    amount?: number;
    currency?: string;
    operation?: string;
    resourceType?: string;
    resourceId?: string;
    ruleViolated?: string;
    automaticAction?: string;
    blocked?: boolean;
  };

  @Prop({ type: Object })
  detection: {
    detectionMethod: 'automatic' | 'manual' | 'external';
    detectionSystem?: string;
    confidence?: number;
    falsePositiveRisk?: number;
  };

  @Prop({ type: Object })
  response: {
    status: 'open' | 'investigating' | 'resolved' | 'false_positive';
    assignedTo?: string;
    resolutionNotes?: string;
    resolvedAt?: Date;
    escalated?: boolean;
    escalatedTo?: string;
  };

  @Prop([String])
  tags: string[];

  @Prop({ type: Object })
  regulatoryImpact: {
    reportable: boolean;
    regulators: string[];
    reportingDeadline?: Date;
    reportStatus?: 'pending' | 'submitted' | 'acknowledged';
  };
}

export type ComplianceEventDocument = ComplianceEvent & Document;
export const ComplianceEventSchema =
  SchemaFactory.createForClass(ComplianceEvent);

/**
 * Regulatory Reporting Schema
 * Manages regulatory reporting requirements and submissions
 */
@Schema({ timestamps: true })
export class RegulatoryReport {
  @Prop({ required: true })
  reportType: string;

  @Prop({ required: true })
  regulator: string;

  @Prop({
    required: true,
    type: Object,
  })
  reportingPeriod: {
    startDate: Date;
    endDate: Date;
    frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'annually';
  };

  @Prop({ required: true, type: String, enum: PermissionScope })
  scope: PermissionScope;

  @Prop()
  organizationId?: string;

  @Prop({ type: Object })
  reportData: {
    format: 'json' | 'xml' | 'csv' | 'pdf';
    schema: string;
    data: any;
    fileUrl?: string;
    fileSize?: number;
    checksum?: string;
  };

  @Prop({ type: Object })
  submission: {
    status:
      | 'draft'
      | 'pending_approval'
      | 'approved'
      | 'submitted'
      | 'acknowledged'
      | 'rejected';
    submittedAt?: Date;
    submittedBy?: string;
    acknowledgmentId?: string;
    acknowledgmentDate?: Date;
    rejectionReason?: string;
  };

  @Prop({ type: Object })
  validation: {
    schemaValid: boolean;
    dataValid: boolean;
    completenessCheck: boolean;
    accuracyScore?: number;
    validationErrors?: string[];
    validatedBy?: string;
    validatedAt?: Date;
  };

  @Prop({ default: false })
  isArchived: boolean;

  @Prop()
  generatedBy: string;

  @Prop()
  approvedBy?: string;
}

export type RegulatoryReportDocument = RegulatoryReport & Document;
export const RegulatoryReportSchema =
  SchemaFactory.createForClass(RegulatoryReport);

/**
 * Audit Trail Schema
 * Enhanced audit logging for compliance
 */
@Schema({ timestamps: true })
export class AuditTrail {
  @Prop({ required: true })
  eventId: string;

  @Prop({ required: true })
  userId: string;

  @Prop()
  impersonatedBy?: string; // If action was performed on behalf of user

  @Prop({ required: true })
  action: string;

  @Prop({ required: true })
  resourceType: string;

  @Prop()
  resourceId?: string;

  @Prop({ required: true, type: String, enum: PermissionScope })
  scope: PermissionScope;

  @Prop()
  organizationId?: string;

  @Prop()
  chamaId?: string;

  @Prop({ type: Object })
  requestData: {
    method: string;
    endpoint: string;
    parameters?: Record<string, any>;
    body?: any;
    userAgent: string;
    ipAddress: string;
    sessionId?: string;
  };

  @Prop({ type: Object })
  responseData: {
    statusCode: number;
    success: boolean;
    error?: string;
    changes?: Array<{
      field: string;
      oldValue: any;
      newValue: any;
    }>;
  };

  @Prop({ type: Object })
  complianceContext: {
    workflowId?: string;
    approvalRequired: boolean;
    approvalStatus?: ApprovalStatus;
    riskLevel?: RiskLevel;
    sensitiveData: boolean;
    dataClassification?: 'public' | 'internal' | 'confidential' | 'restricted';
  };

  @Prop({ type: Object })
  businessContext: {
    amount?: number;
    currency?: string;
    transactionType?: string;
    counterparty?: string;
    businessJustification?: string;
  };

  @Prop([String])
  tags: string[];

  @Prop({ default: false })
  isArchived: boolean;

  @Prop()
  retentionDate: Date; // When this record can be deleted
}

export interface AuditTrailDocument extends AuditTrail, Document {
  createdAt: Date;
  updatedAt: Date;
}
export const AuditTrailSchema = SchemaFactory.createForClass(AuditTrail);
