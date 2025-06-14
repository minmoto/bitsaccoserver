import {
  createParamDecorator,
  ExecutionContext,
  SetMetadata,
  applyDecorators,
  UseGuards,
} from '@nestjs/common';
import {
  SACCOAuthGuard,
  RequirePermissions,
  RequireScope,
} from '../guards/sacco-auth.guard';
import {
  SACCOAuthenticatedRequest,
  SACCOAuthenticatedUser,
  Permission,
  PermissionScope,
} from '../sacco-types';

/**
 * Decorator to extract service context from request
 * Automatically resolves scope and permissions based on request parameters
 */
export const ServiceContext = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<SACCOAuthenticatedRequest>();
    const user = request.user;

    if (!user) {
      return null;
    }

    // Extract context parameters from request
    const organizationId =
      request.params?.organizationId ||
      (request.query?.organizationId as string);
    const chamaId =
      request.params?.chamaId || (request.query?.chamaId as string);

    // Determine scope based on parameters
    let scope = PermissionScope.GLOBAL;
    if (chamaId) {
      scope = PermissionScope.CHAMA;
    } else if (organizationId) {
      scope = PermissionScope.ORGANIZATION;
    }

    return {
      userId: user.userId,
      user,
      scope,
      organizationId,
      chamaId,
      permissions: user.contextPermissions || [],
    };
  },
);

/**
 * Decorator to extract current user from request
 */
export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): SACCOAuthenticatedUser => {
    const request = ctx.switchToHttp().getRequest<SACCOAuthenticatedRequest>();
    return request.user;
  },
);

/**
 * Decorator to extract organization ID from request
 */
export const OrganizationId = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): string | undefined => {
    const request = ctx.switchToHttp().getRequest<SACCOAuthenticatedRequest>();
    return (
      request.params?.organizationId ||
      (request.query?.organizationId as string)
    );
  },
);

/**
 * Decorator to extract chama ID from request
 */
export const ChamaId = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): string | undefined => {
    const request = ctx.switchToHttp().getRequest<SACCOAuthenticatedRequest>();
    return request.params?.chamaId || (request.query?.chamaId as string);
  },
);

/**
 * Combined decorator for context-aware service endpoints
 * Automatically applies authentication, authorization, and context resolution
 */
export function ContextAwareEndpoint(
  permissions: Permission[] = [],
  scope: PermissionScope = PermissionScope.GLOBAL,
) {
  return applyDecorators(
    UseGuards(SACCOAuthGuard),
    RequirePermissions(...permissions),
    RequireScope(scope),
    SetMetadata('contextAware', true),
  );
}

/**
 * Decorator for global scope operations
 */
export function GlobalScope(permissions: Permission[] = []) {
  return ContextAwareEndpoint(permissions, PermissionScope.GLOBAL);
}

/**
 * Decorator for organization scope operations
 */
export function OrganizationScope(permissions: Permission[] = []) {
  return ContextAwareEndpoint(permissions, PermissionScope.ORGANIZATION);
}

/**
 * Decorator for chama scope operations
 */
export function ChamaScope(permissions: Permission[] = []) {
  return ContextAwareEndpoint(permissions, PermissionScope.CHAMA);
}

/**
 * Decorator for personal scope operations
 */
export function PersonalScope(permissions: Permission[] = []) {
  return ContextAwareEndpoint(permissions, PermissionScope.PERSONAL);
}

/**
 * Decorator for multi-scope operations
 * Allows operation to work in multiple scopes
 */
export function MultiScope(
  allowedScopes: PermissionScope[],
  permissions: Permission[] = [],
) {
  return (
    target: any,
    propertyKey?: string,
    descriptor?: PropertyDescriptor,
  ) => {
    // Apply basic auth and permissions
    UseGuards(SACCOAuthGuard)(target, propertyKey, descriptor);
    RequirePermissions(...permissions)(target, propertyKey, descriptor);

    // Set metadata for allowed scopes
    SetMetadata('allowedScopes', allowedScopes)(
      target,
      propertyKey,
      descriptor,
    );
    SetMetadata('contextAware', true)(target, propertyKey, descriptor);
    SetMetadata('multiScope', true)(target, propertyKey, descriptor);
  };
}

/**
 * Decorator for cross-scope operations
 * For operations that interact between different scopes
 */
export function CrossScope(
  sourceScope: PermissionScope,
  targetScope: PermissionScope,
  permissions: Permission[] = [],
) {
  return applyDecorators(
    UseGuards(SACCOAuthGuard),
    RequirePermissions(...permissions),
    SetMetadata('crossScope', true),
    SetMetadata('sourceScope', sourceScope),
    SetMetadata('targetScope', targetScope),
  );
}

/**
 * Decorator for operations requiring approval workflow
 */
export function RequiresApproval(
  approverRoles: string[] = [],
  approverPermissions: Permission[] = [],
) {
  return applyDecorators(
    SetMetadata('requiresApproval', true),
    SetMetadata('approverRoles', approverRoles),
    SetMetadata('approverPermissions', approverPermissions),
  );
}

/**
 * Decorator for operations with rate limiting
 */
export function RateLimit(
  maxOperationsPerHour?: number,
  maxOperationsPerDay?: number,
  maxAmountPerOperation?: number,
) {
  return SetMetadata('rateLimits', {
    maxOperationsPerHour,
    maxOperationsPerDay,
    maxAmountPerOperation,
  });
}

/**
 * Decorator for financial operations with amount limits
 */
export function FinancialOperation(
  maxAmount?: number,
  requiresApprovalAbove?: number,
  permissions: Permission[] = [],
) {
  return applyDecorators(
    ContextAwareEndpoint(permissions),
    SetMetadata('financialOperation', true),
    SetMetadata('maxAmount', maxAmount),
    SetMetadata('requiresApprovalAbove', requiresApprovalAbove),
  );
}

/**
 * Decorator metadata keys
 */
export const CONTEXT_AWARE_KEY = 'contextAware';
export const MULTI_SCOPE_KEY = 'multiScope';
export const CROSS_SCOPE_KEY = 'crossScope';
export const REQUIRES_APPROVAL_KEY = 'requiresApproval';
export const RATE_LIMITS_KEY = 'rateLimits';
export const FINANCIAL_OPERATION_KEY = 'financialOperation';

/**
 * Utility function to check if a method is context-aware
 */
export function isContextAware(target: any, methodName: string): boolean {
  return Reflect.getMetadata(CONTEXT_AWARE_KEY, target, methodName) === true;
}

/**
 * Utility function to get allowed scopes for a method
 */
export function getAllowedScopes(
  target: any,
  methodName: string,
): PermissionScope[] {
  return Reflect.getMetadata('allowedScopes', target, methodName) || [];
}

/**
 * Utility function to check if operation requires approval
 */
export function requiresApproval(target: any, methodName: string): boolean {
  return (
    Reflect.getMetadata(REQUIRES_APPROVAL_KEY, target, methodName) === true
  );
}

/**
 * Utility function to get rate limits
 */
export function getRateLimits(target: any, methodName: string): any {
  return Reflect.getMetadata(RATE_LIMITS_KEY, target, methodName);
}
