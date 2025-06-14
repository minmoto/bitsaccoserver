import {
  Injectable,
  NotFoundException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  CreateOrganizationDto,
  UpdateOrganizationDto,
} from './organization.dto';
import {
  OrganizationDocument,
  OrganizationMember,
  OrganizationMemberDocument,
} from './schemas/organization.schema';
import { UserRole } from './types';

@Injectable()
export class OrganizationService {
  private readonly logger = new Logger(OrganizationService.name);

  constructor(
    @InjectModel(OrganizationDocument.name)
    private organizationModel: Model<OrganizationDocument>,
    @InjectModel(OrganizationMember.name)
    private organizationMemberModel: Model<OrganizationMemberDocument>,
  ) {}

  async create(
    createOrganizationDto: CreateOrganizationDto,
    userId: string,
    userEmail: string,
  ): Promise<OrganizationDocument> {
    // Check if organization name already exists
    const existingOrg = await this.organizationModel.findOne({
      name: createOrganizationDto.name,
    });
    if (existingOrg) {
      throw new ConflictException('Organization name already exists');
    }

    // Create organization
    const organization = new this.organizationModel({
      ...createOrganizationDto,
      ownerId: userId,
      ownerEmail: userEmail,
      limits: {
        maxApiKeys: 10,
        maxMonthlyVolume: 1000000,
        maxDailyRequests: 10000,
      },
      settings: {},
    });

    const savedOrg = await organization.save();

    // Add owner as admin member
    try {
      await this.addMember(
        savedOrg._id.toString(),
        userId,
        UserRole.ADMIN,
        userId,
      );
    } catch (error) {
      this.logger.debug(
        `Failed to add owner as member during organization creation: ${JSON.stringify(
          {
            organizationId: savedOrg._id.toString(),
            userId,
            error: error.message,
          },
        )}`,
      );
      throw error; // Re-throw to ensure organization creation fails if membership fails
    }

    return savedOrg;
  }

  async findAll(userId: string): Promise<OrganizationDocument[]> {
    // Find all organizations where user is a member
    const memberships = await this.organizationMemberModel
      .find({ userId, isActive: true })
      .select('organizationId');

    const orgIds = memberships.map((m) => m.organizationId);

    return this.organizationModel.find({
      _id: { $in: orgIds },
      isActive: true,
    });
  }

  async findOne(id: string): Promise<OrganizationDocument> {
    const organization = await this.organizationModel.findById(id);
    if (!organization) {
      throw new NotFoundException('Organization not found');
    }
    return organization;
  }

  async update(
    id: string,
    updateOrganizationDto: UpdateOrganizationDto,
  ): Promise<OrganizationDocument> {
    const organization = await this.organizationModel.findByIdAndUpdate(
      id,
      updateOrganizationDto,
      { new: true },
    );

    if (!organization) {
      throw new NotFoundException('Organization not found');
    }

    return organization;
  }

  async delete(id: string): Promise<void> {
    const result = await this.organizationModel.findByIdAndUpdate(
      id,
      { isActive: false },
      { new: true },
    );

    if (!result) {
      throw new NotFoundException('Organization not found');
    }

    // Deactivate all memberships
    await this.organizationMemberModel.updateMany(
      { organizationId: id },
      { isActive: false },
    );
  }

  async addMember(
    organizationId: string,
    userId: string,
    role: UserRole,
    invitedBy: string,
  ): Promise<OrganizationMember> {
    this.logger.debug(
      `Adding member - organizationId: ${organizationId}, userId: ${userId}, role: ${role}, invitedBy: ${invitedBy}`,
    );

    // Validate input parameters
    if (!organizationId || !userId || !role || !invitedBy) {
      this.logger.error(
        `Missing required parameters for addMember: ${JSON.stringify({ organizationId, userId, role, invitedBy })}`,
      );
      throw new Error('Missing required parameters for adding member');
    }

    // Check if user is already a member
    const existingMember = await this.organizationMemberModel.findOne({
      organizationId,
      userId,
    });

    if (existingMember) {
      if (existingMember.isActive) {
        throw new ConflictException(
          'User is already a member of this organization',
        );
      }
      // Reactivate existing membership
      existingMember.isActive = true;
      existingMember.role = role;
      existingMember.joinedAt = new Date();
      return existingMember.save();
    }

    const member = new this.organizationMemberModel({
      organizationId,
      userId,
      role,
      invitedBy,
      invitedAt: new Date(),
      joinedAt: new Date(),
    });

    return member.save();
  }

  async getMembers(organizationId: string): Promise<OrganizationMember[]> {
    return this.organizationMemberModel.find({
      organizationId,
      isActive: true,
    });
  }

  async removeMember(organizationId: string, userId: string): Promise<void> {
    const result = await this.organizationMemberModel.findOneAndUpdate(
      { organizationId, userId },
      { isActive: false },
      { new: true },
    );

    if (!result) {
      throw new NotFoundException('Member not found');
    }
  }

  async updateMemberRole(
    organizationId: string,
    userId: string,
    role: UserRole,
  ): Promise<OrganizationMember> {
    const member = await this.organizationMemberModel.findOneAndUpdate(
      { organizationId, userId, isActive: true },
      { role },
      { new: true },
    );

    if (!member) {
      throw new NotFoundException('Member not found');
    }

    return member;
  }
}
