import { getModelToken } from '@nestjs/mongoose';
import { Test, TestingModule } from '@nestjs/testing';
import { OrganizationService } from '../common/organization.service';
import {
  OrganizationDocument,
  OrganizationMember,
} from '../common/schemas/organization.schema';

describe('OrganizationService', () => {
  let service: OrganizationService;
  let mockOrganizationModel: any;
  let mockOrganizationMemberModel: any;

  beforeEach(async () => {
    mockOrganizationModel = {
      find: jest.fn(),
      findById: jest.fn(),
      findOne: jest.fn(),
      create: jest.fn(),
      findByIdAndUpdate: jest.fn(),
      findByIdAndDelete: jest.fn(),
      exec: jest.fn(),
    };

    mockOrganizationMemberModel = {
      find: jest.fn(),
      findOne: jest.fn(),
      create: jest.fn(),
      updateMany: jest.fn(),
      findOneAndUpdate: jest.fn(),
      save: jest.fn(),
      select: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        OrganizationService,
        {
          provide: getModelToken(OrganizationDocument.name),
          useValue: mockOrganizationModel,
        },
        {
          provide: getModelToken(OrganizationMember.name),
          useValue: mockOrganizationMemberModel,
        },
      ],
    }).compile();

    service = module.get<OrganizationService>(OrganizationService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create a new organization', async () => {
      const createDto = {
        name: 'Test Org',
        description: 'Test Description',
        type: 'business' as const,
        country: 'KE',
      };

      const mockOrg = {
        _id: 'org-id',
        ...createDto,
        save: jest.fn().mockResolvedValue({ _id: 'org-id', ...createDto }),
      };

      // Mock findOne to return null (no existing org)
      mockOrganizationModel.findOne.mockResolvedValue(null);

      // Mock the constructor and add static methods
      const MockOrganizationConstructor: any = jest.fn(() => mockOrg);
      Object.assign(MockOrganizationConstructor, mockOrganizationModel);
      (service as any).organizationModel = MockOrganizationConstructor;

      // Mock the OrganizationMember model methods
      mockOrganizationMemberModel.findOne.mockResolvedValue(null);
      const mockMember = {
        save: jest.fn().mockResolvedValue({ userId: 'user-id', role: 'admin' }),
      };
      const MockMemberConstructor: any = jest.fn(() => mockMember);
      Object.assign(MockMemberConstructor, mockOrganizationMemberModel);
      (service as any).organizationMemberModel = MockMemberConstructor;

      const result = await service.create(
        createDto,
        'user-id',
        'user@example.com',
      );
      expect((result as any)._id).toBe('org-id');
      expect(MockOrganizationConstructor).toHaveBeenCalled();
      expect(mockOrg.save).toHaveBeenCalled();
    });
  });

  describe('findAll', () => {
    it('should find organizations for a user', async () => {
      const mockMemberships = [
        { organizationId: 'org-1' },
        { organizationId: 'org-2' },
      ];
      const mockOrgs = [{ _id: 'org-1' }, { _id: 'org-2' }];

      mockOrganizationMemberModel.find.mockReturnValue({
        select: jest.fn().mockResolvedValue(mockMemberships),
      });

      mockOrganizationModel.find.mockResolvedValue(mockOrgs);

      const result = await service.findAll('user-id');
      expect(result).toEqual(mockOrgs);
      expect(mockOrganizationMemberModel.find).toHaveBeenCalledWith({
        userId: 'user-id',
        isActive: true,
      });
    });
  });
});
