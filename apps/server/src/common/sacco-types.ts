import { Request } from 'express';

/**
 * SACCO-specific role hierarchy with dual-scope permissions
 * Service-level roles: System-wide permissions
 * Group-level roles: Context-specific permissions within organizations/chamas
 */

// Service-level roles (system-wide)
export enum ServiceRole {
  SYSTEM_ADMIN = 'system_admin', // Full configuration access
  ADMIN = 'admin', // User management, service configuration
  MEMBER = 'member', // Basic service access
}

// Group-level roles (context-specific within organizations/chamas)
export enum GroupRole {
  // Organization-level roles
  SACCO_OWNER = 'sacco_owner', // SACCO founder/owner
  SACCO_ADMIN = 'sacco_admin', // Full SACCO management
  SACCO_MANAGER = 'sacco_manager', // Operations management
  SACCO_TREASURER = 'sacco_treasurer', // Financial oversight
  SACCO_SECRETARY = 'sacco_secretary', // Record keeping

  // Chama-level roles
  CHAMA_LEADER = 'chama_leader', // Chama leadership
  CHAMA_TREASURER = 'chama_treasurer', // Chama finances
  CHAMA_SECRETARY = 'chama_secretary', // Chama records
  CHAMA_MEMBER = 'chama_member', // Basic chama participation

  // Cross-group roles
  VIEWER = 'viewer', // Read-only access
}

// Permission scopes for context-aware access
export enum PermissionScope {
  GLOBAL = 'global', // System-wide access
  ORGANIZATION = 'organization', // SACCO-level access
  CHAMA = 'chama', // Chama-level access
  PERSONAL = 'personal', // Individual access
}

// Granular permissions for fine-grained access control
export enum Permission {
  // System administration
  SYSTEM_CONFIG = 'system:config',
  SYSTEM_MONITOR = 'system:monitor',
  SYSTEM_BACKUP = 'system:backup',

  // User management
  USER_CREATE = 'user:create',
  USER_READ = 'user:read',
  USER_UPDATE = 'user:update',
  USER_DELETE = 'user:delete',
  USER_INVITE = 'user:invite',

  // Organization management
  ORG_CREATE = 'org:create',
  ORG_READ = 'org:read',
  ORG_UPDATE = 'org:update',
  ORG_DELETE = 'org:delete',
  ORG_SETTINGS = 'org:settings',

  // Chama management
  CHAMA_CREATE = 'chama:create',
  CHAMA_READ = 'chama:read',
  CHAMA_UPDATE = 'chama:update',
  CHAMA_DELETE = 'chama:delete',
  CHAMA_INVITE = 'chama:invite',

  // Financial operations
  FINANCE_READ = 'finance:read',
  FINANCE_DEPOSIT = 'finance:deposit',
  FINANCE_WITHDRAW = 'finance:withdraw',
  FINANCE_TRANSFER = 'finance:transfer',
  FINANCE_APPROVE = 'finance:approve',

  // Shares management
  SHARES_CREATE = 'shares:create',
  SHARES_READ = 'shares:read',
  SHARES_TRADE = 'shares:trade',
  SHARES_APPROVE = 'shares:approve',

  // Loans management
  LOAN_APPLY = 'loan:apply',
  LOAN_READ = 'loan:read',
  LOAN_APPROVE = 'loan:approve',
  LOAN_DISBURSE = 'loan:disburse',

  // Reports and analytics
  REPORTS_READ = 'reports:read',
  REPORTS_EXPORT = 'reports:export',

  // Governance
  GOVERNANCE_VOTE = 'governance:vote',
  GOVERNANCE_PROPOSE = 'governance:propose',
  GOVERNANCE_MODERATE = 'governance:moderate',
}

/**
 * Dual-scope permission assignment
 * Users have both service-level and context-specific permissions
 */
export interface UserPermissions {
  serviceRole: ServiceRole;
  servicePermissions: Permission[];

  // Context-specific permissions
  groupMemberships: GroupMembership[];
}

export interface GroupMembership {
  groupId: string;
  groupType: 'organization' | 'chama';
  role: GroupRole;
  permissions: Permission[];
  scope: PermissionScope;
  isActive: boolean;
  joinedAt: Date;
  invitedBy?: string;
}

/**
 * Enhanced authenticated user with dual-scope context
 */
export interface SACCOAuthenticatedUser {
  // Basic user info
  userId: string;
  email: string;
  authMethod: 'jwt' | 'api-key';

  // Service-level permissions
  serviceRole: ServiceRole;
  servicePermissions: Permission[];

  // Current context
  currentOrganizationId?: string;
  currentChamaId?: string;
  currentScope: PermissionScope;

  // All group memberships
  groupMemberships: GroupMembership[];

  // Resolved permissions for current context
  contextPermissions: Permission[];
}

export interface SACCOAuthenticatedRequest extends Request {
  user: SACCOAuthenticatedUser;
  organizationId?: string;
  chamaId?: string;
  scope: PermissionScope;
}

/**
 * Permission matrix for role-based access control
 */
export const ROLE_PERMISSIONS: Record<ServiceRole | GroupRole, Permission[]> = {
  // Service-level role permissions
  [ServiceRole.SYSTEM_ADMIN]: [
    Permission.SYSTEM_CONFIG,
    Permission.SYSTEM_MONITOR,
    Permission.SYSTEM_BACKUP,
    Permission.USER_CREATE,
    Permission.USER_READ,
    Permission.USER_UPDATE,
    Permission.USER_DELETE,
    Permission.ORG_CREATE,
    Permission.ORG_READ,
    Permission.ORG_UPDATE,
    Permission.ORG_DELETE,
    Permission.REPORTS_READ,
    Permission.REPORTS_EXPORT,
  ],

  [ServiceRole.ADMIN]: [
    Permission.USER_CREATE,
    Permission.USER_READ,
    Permission.USER_UPDATE,
    Permission.USER_INVITE,
    Permission.ORG_READ,
    Permission.ORG_UPDATE,
    Permission.ORG_SETTINGS,
    Permission.REPORTS_READ,
  ],

  [ServiceRole.MEMBER]: [
    Permission.USER_READ,
    Permission.ORG_READ,
    Permission.FINANCE_READ,
    Permission.SHARES_READ,
    Permission.LOAN_READ,
  ],

  // Group-level role permissions
  [GroupRole.SACCO_OWNER]: [
    Permission.ORG_UPDATE,
    Permission.ORG_DELETE,
    Permission.ORG_SETTINGS,
    Permission.USER_INVITE,
    Permission.CHAMA_CREATE,
    Permission.CHAMA_READ,
    Permission.CHAMA_UPDATE,
    Permission.CHAMA_DELETE,
    Permission.FINANCE_READ,
    Permission.FINANCE_APPROVE,
    Permission.SHARES_CREATE,
    Permission.SHARES_READ,
    Permission.SHARES_APPROVE,
    Permission.LOAN_APPROVE,
    Permission.LOAN_DISBURSE,
    Permission.REPORTS_READ,
    Permission.REPORTS_EXPORT,
    Permission.GOVERNANCE_MODERATE,
  ],

  [GroupRole.SACCO_ADMIN]: [
    Permission.ORG_READ,
    Permission.ORG_UPDATE,
    Permission.USER_INVITE,
    Permission.CHAMA_CREATE,
    Permission.CHAMA_READ,
    Permission.CHAMA_UPDATE,
    Permission.FINANCE_READ,
    Permission.FINANCE_APPROVE,
    Permission.SHARES_READ,
    Permission.SHARES_APPROVE,
    Permission.LOAN_APPROVE,
    Permission.REPORTS_READ,
    Permission.GOVERNANCE_MODERATE,
  ],

  [GroupRole.SACCO_MANAGER]: [
    Permission.ORG_READ,
    Permission.CHAMA_READ,
    Permission.CHAMA_UPDATE,
    Permission.FINANCE_READ,
    Permission.SHARES_READ,
    Permission.LOAN_READ,
    Permission.REPORTS_READ,
    Permission.GOVERNANCE_PROPOSE,
  ],

  [GroupRole.SACCO_TREASURER]: [
    Permission.ORG_READ,
    Permission.FINANCE_READ,
    Permission.FINANCE_DEPOSIT,
    Permission.FINANCE_WITHDRAW,
    Permission.FINANCE_TRANSFER,
    Permission.SHARES_READ,
    Permission.LOAN_READ,
    Permission.REPORTS_READ,
  ],

  [GroupRole.SACCO_SECRETARY]: [
    Permission.ORG_READ,
    Permission.USER_READ,
    Permission.CHAMA_READ,
    Permission.FINANCE_READ,
    Permission.REPORTS_READ,
    Permission.GOVERNANCE_VOTE,
  ],

  [GroupRole.CHAMA_LEADER]: [
    Permission.CHAMA_READ,
    Permission.CHAMA_UPDATE,
    Permission.CHAMA_INVITE,
    Permission.FINANCE_READ,
    Permission.FINANCE_APPROVE,
    Permission.SHARES_READ,
    Permission.LOAN_READ,
    Permission.REPORTS_READ,
    Permission.GOVERNANCE_VOTE,
    Permission.GOVERNANCE_PROPOSE,
  ],

  [GroupRole.CHAMA_TREASURER]: [
    Permission.CHAMA_READ,
    Permission.FINANCE_READ,
    Permission.FINANCE_DEPOSIT,
    Permission.FINANCE_WITHDRAW,
    Permission.FINANCE_TRANSFER,
    Permission.SHARES_READ,
    Permission.SHARES_TRADE,
    Permission.LOAN_APPLY,
    Permission.REPORTS_READ,
  ],

  [GroupRole.CHAMA_SECRETARY]: [
    Permission.CHAMA_READ,
    Permission.FINANCE_READ,
    Permission.SHARES_READ,
    Permission.LOAN_READ,
    Permission.REPORTS_READ,
    Permission.GOVERNANCE_VOTE,
  ],

  [GroupRole.CHAMA_MEMBER]: [
    Permission.CHAMA_READ,
    Permission.FINANCE_READ,
    Permission.FINANCE_DEPOSIT,
    Permission.SHARES_READ,
    Permission.SHARES_TRADE,
    Permission.LOAN_APPLY,
    Permission.GOVERNANCE_VOTE,
  ],

  [GroupRole.VIEWER]: [
    Permission.ORG_READ,
    Permission.CHAMA_READ,
    Permission.FINANCE_READ,
    Permission.SHARES_READ,
    Permission.LOAN_READ,
    Permission.REPORTS_READ,
  ],
};

/**
 * Permission inheritance rules
 * Higher roles inherit permissions from lower roles within the same scope
 */
export const ROLE_HIERARCHY: Record<
  ServiceRole | GroupRole,
  (ServiceRole | GroupRole)[]
> = {
  // Service-level hierarchy
  [ServiceRole.SYSTEM_ADMIN]: [ServiceRole.ADMIN, ServiceRole.MEMBER],
  [ServiceRole.ADMIN]: [ServiceRole.MEMBER],
  [ServiceRole.MEMBER]: [],

  // Organization-level hierarchy
  [GroupRole.SACCO_OWNER]: [
    GroupRole.SACCO_ADMIN,
    GroupRole.SACCO_MANAGER,
    GroupRole.SACCO_TREASURER,
    GroupRole.SACCO_SECRETARY,
  ],
  [GroupRole.SACCO_ADMIN]: [
    GroupRole.SACCO_MANAGER,
    GroupRole.SACCO_TREASURER,
    GroupRole.SACCO_SECRETARY,
  ],
  [GroupRole.SACCO_MANAGER]: [GroupRole.SACCO_SECRETARY],
  [GroupRole.SACCO_TREASURER]: [],
  [GroupRole.SACCO_SECRETARY]: [GroupRole.VIEWER],

  // Chama-level hierarchy
  [GroupRole.CHAMA_LEADER]: [
    GroupRole.CHAMA_TREASURER,
    GroupRole.CHAMA_SECRETARY,
    GroupRole.CHAMA_MEMBER,
  ],
  [GroupRole.CHAMA_TREASURER]: [GroupRole.CHAMA_MEMBER],
  [GroupRole.CHAMA_SECRETARY]: [GroupRole.CHAMA_MEMBER],
  [GroupRole.CHAMA_MEMBER]: [GroupRole.VIEWER],
  [GroupRole.VIEWER]: [],
};
