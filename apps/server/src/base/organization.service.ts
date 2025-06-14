import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  SACCOOrganization,
  SACCOOrganizationDocument,
  Chama,
  ChamaDocument,
  SACCOMember,
  SACCOMemberDocument,
  SACCOOrganizationMembership,
  SACCOOrganizationMembershipDocument,
  ChamaMembership,
  ChamaMembershipDocument,
  GroupRelationship,
  GroupRelationshipDocument,
} from '../common';
import {
  ServiceRole,
  GroupRole,
  Permission,
  PermissionScope,
  GroupMembership,
} from '../common';
import { PermissionService } from './permission.service';

/**
 * Service for managing SACCO organizational structures
 * Handles members, organizations, chamas, and their relationships
 */
@Injectable()
export class SACCOOrganizationService {
  constructor(
    @InjectModel(SACCOOrganization.name)
    private saccoOrganizationModel: Model<SACCOOrganizationDocument>,
    @InjectModel(Chama.name)
    private chamaModel: Model<ChamaDocument>,
    @InjectModel(SACCOMember.name)
    private memberModel: Model<SACCOMemberDocument>,
    @InjectModel(SACCOOrganizationMembership.name)
    private orgMembershipModel: Model<SACCOOrganizationMembershipDocument>,
    @InjectModel(ChamaMembership.name)
    private chamaMembershipModel: Model<ChamaMembershipDocument>,
    @InjectModel(GroupRelationship.name)
    private groupRelationshipModel: Model<GroupRelationshipDocument>,
    private permissionService: PermissionService,
  ) {}

  // SACCO Organization Management

  /**
   * Create a new SACCO organization
   */
  async createSACCO(
    organizationData: Partial<SACCOOrganization>,
  ): Promise<SACCOOrganizationDocument> {
    // Check if organization name already exists
    const existingOrg = await this.saccoOrganizationModel.findOne({
      name: organizationData.name,
    });
    if (existingOrg) {
      throw new ConflictException('Organization name already exists');
    }

    // Set default values for new SACCO
    const defaultSACCO = {
      ...organizationData,
      organizationType: 'sacco',
      governance: {
        boardStructure: {},
        meetingSchedule: {
          regularMeetings: 'monthly' as const,
        },
        votingRules: {
          quorumPercentage: 50,
          majorityThreshold: 50,
          allowProxyVoting: false,
        },
        membershipRules: {
          minimumShareCapital: 1000,
          membershipFee: 500,
          autoApproval: false,
        },
      },
      financialConfig: {
        baseCurrency: 'KES',
        shareValue: 100,
        dividendPolicy: {
          distributionFrequency: 'annually' as const,
          minimumReserveRatio: 0.2,
        },
        loanPolicy: {
          maximumLoanMultiplier: 3,
          defaultInterestRate: 0.12,
          maximumLoanTerm: 12,
          collateralRequirement: false,
        },
      },
      limits: {
        maxApiKeys: 10,
        maxMonthlyVolume: 1000000,
        maxDailyRequests: 10000,
      },
      settings: {
        smsNotifications: true,
        emailNotifications: true,
        autoApproveLoans: false,
        autoApproveMembers: false,
      },
      compliance: {
        regulatoryReporting: true,
        auditTrail: true,
        dataRetentionPeriod: 2555, // 7 years
      },
      ...organizationData,
    };

    const organization = new this.saccoOrganizationModel(defaultSACCO);
    const savedOrg = await organization.save();

    // Create owner membership
    if (organizationData.ownerId) {
      await this.addOrganizationMember(
        savedOrg._id.toString(),
        organizationData.ownerId,
        GroupRole.SACCO_OWNER,
        organizationData.ownerId, // self-invitation
      );
    }

    return savedOrg;
  }

  /**
   * Get SACCO organization by ID
   */
  async getSACCO(organizationId: string): Promise<SACCOOrganizationDocument> {
    const organization =
      await this.saccoOrganizationModel.findById(organizationId);
    if (!organization) {
      throw new NotFoundException('SACCO organization not found');
    }
    return organization;
  }

  /**
   * Update SACCO organization
   */
  async updateSACCO(
    organizationId: string,
    updateData: Partial<SACCOOrganization>,
  ): Promise<SACCOOrganizationDocument> {
    const organization = await this.saccoOrganizationModel.findByIdAndUpdate(
      organizationId,
      updateData,
      { new: true, runValidators: true },
    );

    if (!organization) {
      throw new NotFoundException('SACCO organization not found');
    }

    return organization;
  }

  // Chama Management

  /**
   * Create a new chama
   */
  async createChama(chamaData: Partial<Chama>): Promise<ChamaDocument> {
    // Set default values for new chama
    const defaultChama = {
      ...chamaData,
      governance: {
        leadership: {
          leader: chamaData.leaderId,
        },
        meetingSchedule: {
          frequency: 'monthly' as const,
        },
        contributionRules: {
          minimumContribution: 1000,
          contributionFrequency: 'monthly' as const,
        },
        membershipRules: {
          inviteOnly: false,
          approvalRequired: true,
        },
      },
      treasury: {
        balance: 0,
        currency: 'KES',
        contributionHistory: {
          totalContributed: 0,
          averageMonthlyContribution: 0,
        },
        loanFund: {
          totalFund: 0,
          availableFund: 0,
          outstandingLoans: 0,
        },
      },
      metrics: {
        memberCount: 0,
        averageAttendance: 0,
        contributionComplianceRate: 100,
        loanDefaultRate: 0,
        monthlyGrowthRate: 0,
      },
      ...chamaData,
    };

    const chama = new this.chamaModel(defaultChama);
    const savedChama = await chama.save();

    // Create leader membership
    if (chamaData.leaderId) {
      await this.addChamaMember(
        savedChama._id.toString(),
        chamaData.leaderId,
        GroupRole.CHAMA_LEADER,
        chamaData.leaderId, // self-invitation
      );
    }

    return savedChama;
  }

  /**
   * Get chama by ID
   */
  async getChama(chamaId: string): Promise<ChamaDocument> {
    const chama = await this.chamaModel.findById(chamaId);
    if (!chama) {
      throw new NotFoundException('Chama not found');
    }
    return chama;
  }

  /**
   * Get all chamas for a SACCO
   */
  async getSACCOChamas(organizationId: string): Promise<ChamaDocument[]> {
    return this.chamaModel.find({
      parentSACCOId: organizationId,
      isActive: true,
    });
  }

  // Member Management

  /**
   * Create or update a member profile
   */
  async createOrUpdateMember(
    memberData: Partial<SACCOMember>,
  ): Promise<SACCOMemberDocument> {
    const existingMember = await this.memberModel.findOne({
      userId: memberData.userId,
    });

    if (existingMember) {
      // Update existing member
      Object.assign(existingMember, memberData);
      return existingMember.save();
    } else {
      // Create new member with defaults
      const defaultMember = {
        ...memberData,
        serviceRole: ServiceRole.MEMBER,
        kyc: {
          status: 'pending' as const,
        },
        preferences: {
          language: 'en',
          timezone: 'Africa/Nairobi',
          notificationChannels: ['sms', 'email'],
          privacySettings: {
            shareProfileWithChama: true,
            shareContactWithMembers: false,
            allowDirectMessages: true,
          },
        },
        financialSummary: {
          totalShares: 0,
          totalSavings: 0,
          totalLoans: 0,
          totalContributions: 0,
        },
      };

      const member = new this.memberModel(defaultMember);
      return member.save();
    }
  }

  /**
   * Get member by user ID
   */
  async getMember(userId: string): Promise<SACCOMemberDocument> {
    const member = await this.memberModel.findOne({ userId });
    if (!member) {
      throw new NotFoundException('Member not found');
    }
    return member;
  }

  // Organization Membership Management

  /**
   * Add member to SACCO organization
   */
  async addOrganizationMember(
    organizationId: string,
    userId: string,
    role: GroupRole,
    invitedBy: string,
    customPermissions: Permission[] = [],
  ): Promise<SACCOOrganizationMembershipDocument> {
    // Check if membership already exists
    const existingMembership = await this.orgMembershipModel.findOne({
      organizationId,
      userId,
    });

    if (existingMembership) {
      if (existingMembership.isActive) {
        throw new ConflictException(
          'User is already a member of this organization',
        );
      } else {
        // Reactivate membership
        existingMembership.isActive = true;
        existingMembership.role = role;
        existingMembership.customPermissions = customPermissions;
        existingMembership.joinedAt = new Date();
        return existingMembership.save();
      }
    }

    // Create new membership
    const membership = new this.orgMembershipModel({
      userId,
      organizationId,
      role,
      customPermissions,
      invitedBy,
      joinedAt: new Date(),
      membershipDetails: {
        sharesPurchased: 0,
        sharesValue: 0,
        membershipFee: 500, // Default fee
        membershipDate: new Date(),
        status: 'probationary',
      },
      financialRelationship: {
        totalDeposits: 0,
        totalWithdrawals: 0,
        currentBalance: 0,
        loansApproved: 0,
        loansRepaid: 0,
        outstandingLoanBalance: 0,
        savingsBalance: 0,
        dividendsReceived: 0,
      },
      participation: {
        meetingsAttended: 0,
        totalMeetings: 0,
        committeeMemberships: [],
      },
    });

    return membership.save();
  }

  /**
   * Add member to chama
   */
  async addChamaMember(
    chamaId: string,
    userId: string,
    role: GroupRole,
    invitedBy: string,
    customPermissions: Permission[] = [],
  ): Promise<ChamaMembershipDocument> {
    // Check if membership already exists
    const existingMembership = await this.chamaMembershipModel.findOne({
      chamaId,
      userId,
    });

    if (existingMembership) {
      if (existingMembership.isActive) {
        throw new ConflictException('User is already a member of this chama');
      } else {
        // Reactivate membership
        existingMembership.isActive = true;
        existingMembership.role = role;
        existingMembership.customPermissions = customPermissions;
        existingMembership.joinedAt = new Date();
        return existingMembership.save();
      }
    }

    // Create new membership
    const membership = new this.chamaMembershipModel({
      userId,
      chamaId,
      role,
      customPermissions,
      invitedBy,
      joinedAt: new Date(),
      membershipDetails: {
        joinDate: new Date(),
        status: 'probationary',
      },
      contributions: {
        totalContributed: 0,
        monthlyContribution: 1000, // Default contribution
        contributionsMissed: 0,
        penaltiesPaid: 0,
        currentBalance: 0,
      },
      loans: {
        loansReceived: 0,
        totalLoanAmount: 0,
        outstandingLoanBalance: 0,
        loansDefaulted: 0,
        creditRating: 'good',
      },
      participation: {
        meetingsAttended: 0,
        totalMeetings: 0,
        leadershipRoles: [],
        eventParticipation: 0,
      },
    });

    // Update chama member count
    await this.chamaModel.findByIdAndUpdate(chamaId, {
      $inc: { 'metrics.memberCount': 1 },
    });

    return membership.save();
  }

  /**
   * Get user's group memberships for permission resolution
   */
  async getUserGroupMemberships(userId: string): Promise<GroupMembership[]> {
    const memberships: GroupMembership[] = [];

    // Get organization memberships
    const orgMemberships = await this.orgMembershipModel.find({
      userId,
      isActive: true,
    });
    for (const membership of orgMemberships) {
      memberships.push({
        groupId: membership.organizationId,
        groupType: 'organization',
        role: membership.role,
        permissions: [
          ...this.permissionService.getGroupRolePermissions(membership.role),
          ...membership.customPermissions,
        ],
        scope: PermissionScope.ORGANIZATION,
        isActive: membership.isActive,
        joinedAt: membership.joinedAt || membership.invitedAt,
        invitedBy: membership.invitedBy,
      });
    }

    // Get chama memberships
    const chamaMemberships = await this.chamaMembershipModel.find({
      userId,
      isActive: true,
    });
    for (const membership of chamaMemberships) {
      memberships.push({
        groupId: membership.chamaId,
        groupType: 'chama',
        role: membership.role,
        permissions: [
          ...this.permissionService.getGroupRolePermissions(membership.role),
          ...membership.customPermissions,
        ],
        scope: PermissionScope.CHAMA,
        isActive: membership.isActive,
        joinedAt: membership.joinedAt || membership.invitedAt,
        invitedBy: membership.invitedBy,
      });
    }

    return memberships;
  }

  /**
   * Update member role in organization
   */
  async updateOrganizationMemberRole(
    organizationId: string,
    userId: string,
    newRole: GroupRole,
    _updatedBy: string,
  ): Promise<SACCOOrganizationMembershipDocument> {
    const membership = await this.orgMembershipModel.findOne({
      organizationId,
      userId,
      isActive: true,
    });

    if (!membership) {
      throw new NotFoundException('Organization membership not found');
    }

    membership.role = newRole;
    return membership.save();
  }

  /**
   * Remove member from organization
   */
  async removeOrganizationMember(
    organizationId: string,
    userId: string,
  ): Promise<void> {
    await this.orgMembershipModel.findOneAndUpdate(
      { organizationId, userId },
      { isActive: false },
    );
  }

  /**
   * Remove member from chama
   */
  async removeChamaMember(chamaId: string, userId: string): Promise<void> {
    await this.chamaMembershipModel.findOneAndUpdate(
      { chamaId, userId },
      { isActive: false, 'membershipDetails.exitDate': new Date() },
    );

    // Update chama member count
    await this.chamaModel.findByIdAndUpdate(chamaId, {
      $inc: { 'metrics.memberCount': -1 },
    });
  }

  /**
   * Create relationship between groups
   */
  async createGroupRelationship(
    parentGroupId: string,
    childGroupId: string,
    relationshipType: 'parent-child' | 'affiliate' | 'partner' | 'federation',
    establishedBy: string,
    details?: any,
  ): Promise<GroupRelationshipDocument> {
    const relationship = new this.groupRelationshipModel({
      parentGroupId,
      childGroupId,
      relationshipType,
      relationshipDetails: {
        establishedDate: new Date(),
        establishedBy,
        ...details,
      },
      sharedServices: [],
    });

    return relationship.save();
  }

  /**
   * Get organization structure with chamas and members
   */
  async getOrganizationStructure(organizationId: string) {
    const [organization, chamas, members] = await Promise.all([
      this.getSACCO(organizationId),
      this.getSACCOChamas(organizationId),
      this.orgMembershipModel
        .find({ organizationId, isActive: true })
        .populate('userId'),
    ]);

    return {
      organization,
      chamas,
      members,
      memberCount: members.length,
      chamaCount: chamas.length,
    };
  }
}
