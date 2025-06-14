import { Document } from 'mongoose';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { ServiceRole, GroupRole, Permission } from '../sacco-types';

/**
 * Enhanced SACCO Organization Schema
 * Supports hierarchical structure with flexible organizational formations
 */
@Schema({ timestamps: true })
export class SACCOOrganization {
  @Prop({ required: true, unique: true })
  name: string;

  @Prop({ required: true })
  country: string;

  @Prop()
  description?: string;

  @Prop({ required: true })
  ownerId: string;

  @Prop({ required: true })
  ownerEmail: string;

  @Prop({
    type: String,
    enum: ['sacco', 'cooperative', 'chama_federation'],
    default: 'sacco',
  })
  organizationType: string;

  // Enhanced KYB details for SACCO compliance
  @Prop({ type: Object })
  kybDetails?: {
    businessRegistrationNumber?: string;
    taxId?: string;
    businessAddress?: string;
    businessType?: string;
    regulatoryLicense?: string;
    registrationDate?: Date;
    status?: 'pending' | 'verified' | 'rejected';
    verifiedAt?: Date;
    verifiedBy?: string;
  };

  // SACCO-specific governance configuration
  @Prop({ type: Object })
  governance: {
    boardStructure: {
      chairperson?: string;
      secretary?: string;
      treasurer?: string;
      members?: string[];
    };
    meetingSchedule: {
      regularMeetings: 'monthly' | 'quarterly' | 'annually';
      agmDate?: Date;
      nextMeetingDate?: Date;
    };
    votingRules: {
      quorumPercentage: number;
      majorityThreshold: number;
      allowProxyVoting: boolean;
    };
    membershipRules: {
      minimumShareCapital: number;
      maximumShareCapital?: number;
      membershipFee: number;
      probationaryPeriod?: number; // in days
      autoApproval: boolean;
    };
  };

  // Financial configuration
  @Prop({ type: Object })
  financialConfig: {
    baseCurrency: string;
    shareValue: number;
    dividendPolicy: {
      distributionFrequency: 'monthly' | 'quarterly' | 'annually';
      minimumReserveRatio: number;
      maximumDividendRate?: number;
    };
    loanPolicy: {
      maximumLoanMultiplier: number; // multiple of shares
      defaultInterestRate: number;
      maximumLoanTerm: number; // in months
      collateralRequirement: boolean;
    };
  };

  @Prop({ default: true })
  isActive: boolean;

  // Enhanced limits and quotas
  @Prop({ type: Object })
  limits: {
    maxMembers?: number;
    maxChamas?: number;
    maxApiKeys: number;
    maxMonthlyVolume: number;
    maxDailyRequests: number;
    maxLoanAmount?: number;
    maxSavingsAmount?: number;
  };

  // Integration and notification settings
  @Prop({ type: Object })
  settings: {
    allowedDomains?: string[];
    webhookUrl?: string;
    notificationEmail?: string;
    smsNotifications: boolean;
    emailNotifications: boolean;
    autoApproveLoans: boolean;
    autoApproveMembers: boolean;
  };

  // Compliance and audit trail
  @Prop({ type: Object })
  compliance: {
    regulatoryReporting: boolean;
    auditTrail: boolean;
    dataRetentionPeriod: number; // in days
    lastAuditDate?: Date;
    nextAuditDate?: Date;
    complianceScore?: number;
  };
}

export type SACCOOrganizationDocument = SACCOOrganization & Document;
export const SACCOOrganizationSchema =
  SchemaFactory.createForClass(SACCOOrganization);

/**
 * Chama Schema - Sub-organizations within SACCOs
 * Supports both independent chamas and SACCO-affiliated chamas
 */
@Schema({ timestamps: true })
export class Chama {
  @Prop({ required: true })
  name: string;

  @Prop()
  description?: string;

  @Prop({ required: true })
  leaderId: string;

  @Prop()
  parentSACCOId?: string; // Optional - for SACCO-affiliated chamas

  @Prop({
    type: String,
    enum: ['independent', 'sacco_affiliated', 'sub_group'],
    default: 'independent',
  })
  chamaType: string;

  // Chama-specific governance
  @Prop({ type: Object })
  governance: {
    leadership: {
      leader?: string;
      treasurer?: string;
      secretary?: string;
    };
    meetingSchedule: {
      frequency: 'weekly' | 'bi-weekly' | 'monthly';
      dayOfWeek?: number; // 0-6 (Sunday-Saturday)
      timeOfDay?: string; // HH:MM format
      nextMeetingDate?: Date;
    };
    contributionRules: {
      minimumContribution: number;
      contributionFrequency: 'weekly' | 'monthly';
      penaltyRate?: number; // for late contributions
      gracePeriod?: number; // in days
    };
    membershipRules: {
      maximumMembers?: number;
      inviteOnly: boolean;
      approvalRequired: boolean;
      probationaryPeriod?: number; // in days
    };
  };

  // Chama treasury and financial management
  @Prop({ type: Object })
  treasury: {
    balance: number;
    currency: string;
    monthlyTarget?: number;
    contributionHistory: {
      totalContributed: number;
      averageMonthlyContribution: number;
      lastContributionDate?: Date;
    };
    loanFund: {
      totalFund: number;
      availableFund: number;
      outstandingLoans: number;
    };
    savingsAccount?: {
      accountNumber?: string;
      bankName?: string;
      accountBalance: number;
    };
  };

  @Prop({ default: true })
  isActive: boolean;

  // Chama activity and performance metrics
  @Prop({ type: Object })
  metrics: {
    memberCount: number;
    averageAttendance: number;
    contributionComplianceRate: number;
    loanDefaultRate: number;
    monthlyGrowthRate: number;
    lastActivityDate?: Date;
  };

  // External integrations (mobile money, banking)
  @Prop({ type: Object })
  integrations: {
    mobileMoney?: {
      provider: 'mpesa' | 'airtel' | 'mtn';
      accountNumber?: string;
      isActive: boolean;
    };
    banking?: {
      bankName?: string;
      accountNumber?: string;
      isActive: boolean;
    };
  };
}

export type ChamaDocument = Chama & Document;
export const ChamaSchema = SchemaFactory.createForClass(Chama);

/**
 * Enhanced Member Schema with dual-scope membership
 * Supports membership in both SACCOs and Chamas
 */
@Schema({ timestamps: true })
export class SACCOMember {
  @Prop({ required: true })
  userId: string;

  @Prop({ required: true })
  email: string;

  @Prop()
  phoneNumber?: string;

  @Prop()
  firstName?: string;

  @Prop()
  lastName?: string;

  @Prop()
  nationalId?: string;

  // Service-level role (system-wide)
  @Prop({
    type: String,
    enum: ServiceRole,
    default: ServiceRole.MEMBER,
  })
  serviceRole: ServiceRole;

  // Member profile and KYC information
  @Prop({ type: Object })
  profile: {
    dateOfBirth?: Date;
    gender?: 'male' | 'female' | 'other';
    occupation?: string;
    employerName?: string;
    monthlyIncome?: number;
    residentialAddress?: string;
    nextOfKin?: {
      name: string;
      relationship: string;
      phoneNumber: string;
    };
  };

  // KYC status and documentation
  @Prop({ type: Object })
  kyc: {
    status: 'pending' | 'verified' | 'rejected';
    documentType?: 'national_id' | 'passport' | 'driving_license';
    documentNumber?: string;
    documentExpiryDate?: Date;
    verifiedAt?: Date;
    verifiedBy?: string;
    rejectionReason?: string;
  };

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ default: false })
  isEmailVerified: boolean;

  @Prop({ default: false })
  isPhoneVerified: boolean;

  // Member preferences and settings
  @Prop({ type: Object })
  preferences: {
    language: string;
    timezone: string;
    notificationChannels: ('sms' | 'email' | 'push' | 'whatsapp')[];
    privacySettings: {
      shareProfileWithChama: boolean;
      shareContactWithMembers: boolean;
      allowDirectMessages: boolean;
    };
  };

  // Financial overview (aggregated across all memberships)
  @Prop({ type: Object })
  financialSummary: {
    totalShares: number;
    totalSavings: number;
    totalLoans: number;
    totalContributions: number;
    creditScore?: number;
    lastTransactionDate?: Date;
  };
}

export type SACCOMemberDocument = SACCOMember & Document;
export const SACCOMemberSchema = SchemaFactory.createForClass(SACCOMember);

/**
 * Organization Membership - Links members to SACCOs with roles
 */
@Schema({ timestamps: true })
export class SACCOOrganizationMembership {
  @Prop({ required: true })
  userId: string;

  @Prop({ required: true })
  organizationId: string;

  @Prop({
    type: String,
    enum: GroupRole,
    required: true,
  })
  role: GroupRole;

  @Prop([{ type: String, enum: Permission }])
  customPermissions: Permission[];

  @Prop({ required: true })
  invitedBy: string;

  @Prop({ default: new Date() })
  invitedAt: Date;

  @Prop()
  joinedAt?: Date;

  @Prop({ default: true })
  isActive: boolean;

  // Membership-specific data
  @Prop({ type: Object })
  membershipDetails: {
    memberNumber?: string;
    sharesPurchased: number;
    sharesValue: number;
    membershipFee: number;
    membershipDate: Date;
    status: 'probationary' | 'active' | 'suspended' | 'terminated';
    suspensionReason?: string;
    probationaryEndDate?: Date;
  };

  // Financial relationship with the SACCO
  @Prop({ type: Object })
  financialRelationship: {
    totalDeposits: number;
    totalWithdrawals: number;
    currentBalance: number;
    loansApproved: number;
    loansRepaid: number;
    outstandingLoanBalance: number;
    savingsBalance: number;
    dividendsReceived: number;
  };

  // Participation and engagement metrics
  @Prop({ type: Object })
  participation: {
    meetingsAttended: number;
    totalMeetings: number;
    lastMeetingDate?: Date;
    committeeMemberships: string[];
    volunteerHours?: number;
  };
}

export type SACCOOrganizationMembershipDocument = SACCOOrganizationMembership &
  Document;
export const SACCOOrganizationMembershipSchema = SchemaFactory.createForClass(
  SACCOOrganizationMembership,
);

/**
 * Chama Membership - Links members to chamas with roles
 */
@Schema({ timestamps: true })
export class ChamaMembership {
  @Prop({ required: true })
  userId: string;

  @Prop({ required: true })
  chamaId: string;

  @Prop({
    type: String,
    enum: GroupRole,
    required: true,
  })
  role: GroupRole;

  @Prop([{ type: String, enum: Permission }])
  customPermissions: Permission[];

  @Prop({ required: true })
  invitedBy: string;

  @Prop({ default: new Date() })
  invitedAt: Date;

  @Prop()
  joinedAt?: Date;

  @Prop({ default: true })
  isActive: boolean;

  // Chama-specific membership data
  @Prop({ type: Object })
  membershipDetails: {
    memberNumber?: string;
    joinDate: Date;
    status: 'probationary' | 'active' | 'suspended' | 'left';
    exitDate?: Date;
    exitReason?: string;
    probationaryEndDate?: Date;
  };

  // Financial relationship with the chama
  @Prop({ type: Object })
  contributions: {
    totalContributed: number;
    monthlyContribution: number;
    lastContributionDate?: Date;
    contributionsMissed: number;
    penaltiesPaid: number;
    currentBalance: number;
  };

  // Chama loans and financial transactions
  @Prop({ type: Object })
  loans: {
    loansReceived: number;
    totalLoanAmount: number;
    outstandingLoanBalance: number;
    loansDefaulted: number;
    lastLoanDate?: Date;
    creditRating: 'excellent' | 'good' | 'fair' | 'poor';
  };

  // Participation in chama activities
  @Prop({ type: Object })
  participation: {
    meetingsAttended: number;
    totalMeetings: number;
    lastMeetingDate?: Date;
    leadershipRoles: string[];
    eventParticipation: number;
  };
}

export type ChamaMembershipDocument = ChamaMembership & Document;
export const ChamaMembershipSchema =
  SchemaFactory.createForClass(ChamaMembership);

/**
 * Cross-group relationships and interactions
 */
@Schema({ timestamps: true })
export class GroupRelationship {
  @Prop({ required: true })
  parentGroupId: string;

  @Prop({ required: true })
  childGroupId: string;

  @Prop({
    type: String,
    enum: ['parent-child', 'affiliate', 'partner', 'federation'],
    required: true,
  })
  relationshipType: string;

  @Prop({ type: Object })
  relationshipDetails: {
    establishedDate: Date;
    establishedBy: string;
    terms?: string;
    benefits?: string[];
    obligations?: string[];
    reviewDate?: Date;
  };

  @Prop({ default: true })
  isActive: boolean;

  // Shared services and integrations
  @Prop([String])
  sharedServices: string[];

  @Prop({ type: Object })
  financialArrangements?: {
    feeSharing?: number; // percentage
    resourceSharing?: boolean;
    jointPrograms?: string[];
  };
}

export type GroupRelationshipDocument = GroupRelationship & Document;
export const GroupRelationshipSchema =
  SchemaFactory.createForClass(GroupRelationship);
