import { Document } from 'mongoose';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { GroupRole } from '@bitsaccoserver/types';

@Schema({ timestamps: true })
export class OrganizationDocument {
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

  @Prop({ type: Object })
  kybDetails?: {
    businessRegistrationNumber?: string;
    taxId?: string;
    businessAddress?: string;
    businessType?: string;
    status?: 'pending' | 'verified' | 'rejected';
  };

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ type: Object })
  limits: {
    maxApiKeys: number;
    maxMonthlyVolume: number;
    maxDailyRequests: number;
  };

  @Prop({ type: Object })
  settings: {
    allowedDomains?: string[];
    webhookUrl?: string;
    notificationEmail?: string;
  };
}

export const OrganizationSchema =
  SchemaFactory.createForClass(OrganizationDocument);

@Schema({ timestamps: true })
export class OrganizationMember {
  @Prop({ required: true })
  memberId: string;

  @Prop({ required: true })
  organizationId: string;

  @Prop({ type: String, enum: GroupRole, required: true })
  role: GroupRole;

  @Prop({ required: true })
  invitedBy: string;

  @Prop()
  invitedAt: Date;

  @Prop()
  joinedAt?: Date;

  @Prop({ default: true })
  isActive: boolean;
}

export type OrganizationMemberDocument = OrganizationMember & Document;

export const OrganizationMemberSchema =
  SchemaFactory.createForClass(OrganizationMember);
