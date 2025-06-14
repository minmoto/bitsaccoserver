import {
  Injectable,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { SACCOAuthenticatedUser, Permission, PermissionScope } from '../common';
import { PermissionService } from './permission.service';
import { SACCOOrganizationService } from './organization.service';

/**
 * Context-aware service framework for SACCO operations
 * Handles service delivery across multiple scopes: global, organization, chama, personal
 */

export interface ServiceContext {
  userId: string;
  scope: PermissionScope;
  organizationId?: string;
  chamaId?: string;
  permissions: Permission[];
  user: SACCOAuthenticatedUser;
}

export interface ServiceOperation {
  name: string;
  requiredPermissions: Permission[];
  allowedScopes: PermissionScope[];
  requiresApproval?: boolean;
  approvalRoles?: string[];
  rateLimits?: {
    maxOperationsPerDay?: number;
    maxOperationsPerHour?: number;
    maxAmountPerOperation?: number;
  };
}

export interface ServiceResult<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  requiresApproval?: boolean;
  approvalId?: string;
  context: ServiceContext;
}

/**
 * Base class for context-aware services
 */
@Injectable()
export abstract class ContextAwareService {
  constructor(
    protected permissionService: PermissionService,
    protected organizationService: SACCOOrganizationService,
  ) {}

  /**
   * Abstract method to define service operations
   */
  abstract getServiceOperations(): Record<string, ServiceOperation>;

  /**
   * Create service context from authenticated user and request parameters
   */
  async createServiceContext(
    user: SACCOAuthenticatedUser,
    organizationId?: string,
    chamaId?: string,
  ): Promise<ServiceContext> {
    // Determine scope based on provided IDs
    let scope = PermissionScope.GLOBAL;
    if (chamaId) {
      scope = PermissionScope.CHAMA;
    } else if (organizationId) {
      scope = PermissionScope.ORGANIZATION;
    }

    // Resolve permissions for the context
    const permissions = this.permissionService.resolveUserPermissions(
      user,
      scope,
      organizationId,
      chamaId,
    );

    return {
      userId: user.userId,
      scope,
      organizationId,
      chamaId,
      permissions,
      user,
    };
  }

  /**
   * Validate service operation in given context
   */
  async validateOperation(
    operationName: string,
    context: ServiceContext,
  ): Promise<void> {
    const operations = this.getServiceOperations();
    const operation = operations[operationName];

    if (!operation) {
      throw new BadRequestException(`Unknown operation: ${operationName}`);
    }

    // Check if operation is allowed in current scope
    if (!operation.allowedScopes.includes(context.scope)) {
      throw new ForbiddenException(
        `Operation ${operationName} not allowed in ${context.scope} scope`,
      );
    }

    // Check permissions
    const hasPermissions = this.permissionService.userHasAllPermissions(
      context.user,
      operation.requiredPermissions,
      context.scope,
      context.organizationId,
      context.chamaId,
    );

    if (!hasPermissions) {
      throw new ForbiddenException(
        `Insufficient permissions for operation: ${operationName}`,
      );
    }
  }

  /**
   * Execute service operation with context validation
   */
  async executeOperation<T>(
    operationName: string,
    context: ServiceContext,
    operationData: any,
  ): Promise<ServiceResult<T>> {
    try {
      // Validate operation
      await this.validateOperation(operationName, context);

      // Execute the operation
      const result = await this.performOperation<T>(
        operationName,
        context,
        operationData,
      );

      return {
        success: true,
        data: result,
        context,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        context,
      };
    }
  }

  /**
   * Abstract method for service-specific operation implementation
   */
  protected abstract performOperation<T>(
    operationName: string,
    context: ServiceContext,
    operationData: any,
  ): Promise<T>;

  /**
   * Check if operation requires approval workflow
   */
  protected requiresApproval(
    operationName: string,
    _context: ServiceContext,
    _operationData: any,
  ): boolean {
    const operations = this.getServiceOperations();
    const operation = operations[operationName];
    return operation.requiresApproval || false;
  }

  /**
   * Cross-scope operation validation
   * For operations that span multiple organizations/chamas
   */
  async validateCrossScope(
    sourceContext: ServiceContext,
    targetContext: ServiceContext,
    operation: string,
  ): Promise<boolean> {
    // Both contexts must have required permissions
    await this.validateOperation(operation, sourceContext);
    await this.validateOperation(operation, targetContext);

    // Additional cross-scope validation logic
    if (
      sourceContext.scope === PermissionScope.CHAMA &&
      targetContext.scope === PermissionScope.CHAMA
    ) {
      // Chama-to-chama operations need additional validation
      return this.validateChamaToChama(sourceContext, targetContext);
    }

    if (
      sourceContext.scope === PermissionScope.ORGANIZATION &&
      targetContext.scope === PermissionScope.CHAMA
    ) {
      // Organization-to-chama operations
      return this.validateOrganizationToChama(sourceContext, targetContext);
    }

    return true;
  }

  /**
   * Validate chama-to-chama operations
   */
  private async validateChamaToChama(
    _sourceContext: ServiceContext,
    _targetContext: ServiceContext,
  ): Promise<boolean> {
    // Check if chamas are related or have partnership agreements
    // This would query the GroupRelationship collection
    return true; // Simplified for now
  }

  /**
   * Validate organization-to-chama operations
   */
  private async validateOrganizationToChama(
    sourceContext: ServiceContext,
    targetContext: ServiceContext,
  ): Promise<boolean> {
    // Check if chama belongs to the organization
    const chama = await this.organizationService.getChama(
      targetContext.chamaId!,
    );
    return chama.parentSACCOId === sourceContext.organizationId;
  }
}

/**
 * Financial Services - Context-aware financial operations
 */
@Injectable()
export class FinancialService extends ContextAwareService {
  getServiceOperations(): Record<string, ServiceOperation> {
    return {
      deposit: {
        name: 'deposit',
        requiredPermissions: [Permission.FINANCE_DEPOSIT],
        allowedScopes: [
          PermissionScope.ORGANIZATION,
          PermissionScope.CHAMA,
          PermissionScope.PERSONAL,
        ],
        rateLimits: {
          maxOperationsPerDay: 10,
          maxAmountPerOperation: 100000,
        },
      },
      withdraw: {
        name: 'withdraw',
        requiredPermissions: [Permission.FINANCE_WITHDRAW],
        allowedScopes: [
          PermissionScope.ORGANIZATION,
          PermissionScope.CHAMA,
          PermissionScope.PERSONAL,
        ],
        requiresApproval: true,
        approvalRoles: ['treasurer', 'leader'],
        rateLimits: {
          maxOperationsPerDay: 5,
          maxAmountPerOperation: 50000,
        },
      },
      transfer: {
        name: 'transfer',
        requiredPermissions: [Permission.FINANCE_TRANSFER],
        allowedScopes: [
          PermissionScope.ORGANIZATION,
          PermissionScope.CHAMA,
          PermissionScope.PERSONAL,
        ],
        requiresApproval: true,
        rateLimits: {
          maxOperationsPerDay: 5,
          maxAmountPerOperation: 25000,
        },
      },
      viewBalance: {
        name: 'viewBalance',
        requiredPermissions: [Permission.FINANCE_READ],
        allowedScopes: [
          PermissionScope.GLOBAL,
          PermissionScope.ORGANIZATION,
          PermissionScope.CHAMA,
          PermissionScope.PERSONAL,
        ],
      },
      generateStatement: {
        name: 'generateStatement',
        requiredPermissions: [Permission.REPORTS_READ],
        allowedScopes: [
          PermissionScope.ORGANIZATION,
          PermissionScope.CHAMA,
          PermissionScope.PERSONAL,
        ],
      },
    };
  }

  protected async performOperation<T>(
    operationName: string,
    context: ServiceContext,
    operationData: any,
  ): Promise<T> {
    switch (operationName) {
      case 'deposit':
        return this.processDeposit(context, operationData) as Promise<T>;
      case 'withdraw':
        return this.processWithdrawal(context, operationData) as Promise<T>;
      case 'transfer':
        return this.processTransfer(context, operationData) as Promise<T>;
      case 'viewBalance':
        return this.getBalance(context) as Promise<T>;
      case 'generateStatement':
        return this.generateStatement(context, operationData) as Promise<T>;
      default:
        throw new BadRequestException(
          `Unsupported operation: ${operationName}`,
        );
    }
  }

  private async processDeposit(
    context: ServiceContext,
    data: any,
  ): Promise<any> {
    // Implementation for deposit based on context scope
    return {
      transactionId: 'TXN001',
      amount: data.amount,
      status: 'completed',
    };
  }

  private async processWithdrawal(
    context: ServiceContext,
    data: any,
  ): Promise<any> {
    // Implementation for withdrawal based on context scope
    return {
      transactionId: 'TXN002',
      amount: data.amount,
      status: 'pending_approval',
    };
  }

  private async processTransfer(
    context: ServiceContext,
    data: any,
  ): Promise<any> {
    // Implementation for transfer based on context scope
    return {
      transactionId: 'TXN003',
      amount: data.amount,
      status: 'completed',
    };
  }

  private async getBalance(context: ServiceContext): Promise<any> {
    // Return balance based on context scope
    return { balance: 10000, currency: 'KES', scope: context.scope };
  }

  private async generateStatement(
    context: ServiceContext,
    data: any,
  ): Promise<any> {
    // Generate financial statement based on context scope
    return { statementId: 'STMT001', period: data.period, format: 'pdf' };
  }
}

/**
 * Shares Service - Context-aware shares management
 */
@Injectable()
export class SharesService extends ContextAwareService {
  getServiceOperations(): Record<string, ServiceOperation> {
    return {
      purchaseShares: {
        name: 'purchaseShares',
        requiredPermissions: [Permission.SHARES_TRADE],
        allowedScopes: [PermissionScope.ORGANIZATION, PermissionScope.PERSONAL],
        rateLimits: {
          maxOperationsPerDay: 3,
        },
      },
      sellShares: {
        name: 'sellShares',
        requiredPermissions: [Permission.SHARES_TRADE],
        allowedScopes: [PermissionScope.ORGANIZATION, PermissionScope.PERSONAL],
        requiresApproval: true,
        rateLimits: {
          maxOperationsPerDay: 2,
        },
      },
      viewShares: {
        name: 'viewShares',
        requiredPermissions: [Permission.SHARES_READ],
        allowedScopes: [
          PermissionScope.GLOBAL,
          PermissionScope.ORGANIZATION,
          PermissionScope.PERSONAL,
        ],
      },
      createOffer: {
        name: 'createOffer',
        requiredPermissions: [Permission.SHARES_CREATE],
        allowedScopes: [PermissionScope.ORGANIZATION],
        requiresApproval: true,
      },
    };
  }

  protected async performOperation<T>(
    operationName: string,
    context: ServiceContext,
    operationData: any,
  ): Promise<T> {
    switch (operationName) {
      case 'purchaseShares':
        return this.purchaseShares(context, operationData) as Promise<T>;
      case 'sellShares':
        return this.sellShares(context, operationData) as Promise<T>;
      case 'viewShares':
        return this.getShares(context) as Promise<T>;
      case 'createOffer':
        return this.createSharesOffer(context, operationData) as Promise<T>;
      default:
        throw new BadRequestException(
          `Unsupported shares operation: ${operationName}`,
        );
    }
  }

  private async purchaseShares(
    context: ServiceContext,
    data: any,
  ): Promise<any> {
    return { sharesPurchased: data.quantity, totalCost: data.quantity * 100 };
  }

  private async sellShares(context: ServiceContext, data: any): Promise<any> {
    return { sharesSold: data.quantity, totalValue: data.quantity * 100 };
  }

  private async getShares(context: ServiceContext): Promise<any> {
    return { totalShares: 50, currentValue: 5000, scope: context.scope };
  }

  private async createSharesOffer(
    context: ServiceContext,
    data: any,
  ): Promise<any> {
    return { offerId: 'OFFER001', sharesOffered: data.quantity };
  }
}

/**
 * Loan Service - Context-aware loan management
 */
@Injectable()
export class LoanService extends ContextAwareService {
  getServiceOperations(): Record<string, ServiceOperation> {
    return {
      applyLoan: {
        name: 'applyLoan',
        requiredPermissions: [Permission.LOAN_APPLY],
        allowedScopes: [
          PermissionScope.ORGANIZATION,
          PermissionScope.CHAMA,
          PermissionScope.PERSONAL,
        ],
        requiresApproval: true,
        rateLimits: {
          maxOperationsPerDay: 1,
        },
      },
      approveLoan: {
        name: 'approveLoan',
        requiredPermissions: [Permission.LOAN_APPROVE],
        allowedScopes: [PermissionScope.ORGANIZATION, PermissionScope.CHAMA],
      },
      disburseLoan: {
        name: 'disburseLoan',
        requiredPermissions: [Permission.LOAN_DISBURSE],
        allowedScopes: [PermissionScope.ORGANIZATION],
      },
      viewLoans: {
        name: 'viewLoans',
        requiredPermissions: [Permission.LOAN_READ],
        allowedScopes: [
          PermissionScope.GLOBAL,
          PermissionScope.ORGANIZATION,
          PermissionScope.CHAMA,
          PermissionScope.PERSONAL,
        ],
      },
      repayLoan: {
        name: 'repayLoan',
        requiredPermissions: [Permission.FINANCE_DEPOSIT],
        allowedScopes: [
          PermissionScope.ORGANIZATION,
          PermissionScope.CHAMA,
          PermissionScope.PERSONAL,
        ],
      },
    };
  }

  protected async performOperation<T>(
    operationName: string,
    context: ServiceContext,
    operationData: any,
  ): Promise<T> {
    switch (operationName) {
      case 'applyLoan':
        return this.applyForLoan(context, operationData) as Promise<T>;
      case 'approveLoan':
        return this.approveLoan(context, operationData) as Promise<T>;
      case 'disburseLoan':
        return this.disburseLoan(context, operationData) as Promise<T>;
      case 'viewLoans':
        return this.getLoans(context) as Promise<T>;
      case 'repayLoan':
        return this.repayLoan(context, operationData) as Promise<T>;
      default:
        throw new BadRequestException(
          `Unsupported loan operation: ${operationName}`,
        );
    }
  }

  private async applyForLoan(context: ServiceContext, data: any): Promise<any> {
    return {
      applicationId: 'LOAN001',
      amount: data.amount,
      status: 'pending_approval',
      scope: context.scope,
    };
  }

  private async approveLoan(context: ServiceContext, data: any): Promise<any> {
    return {
      loanId: data.loanId,
      status: 'approved',
      approvedBy: context.userId,
    };
  }

  private async disburseLoan(context: ServiceContext, data: any): Promise<any> {
    return { loanId: data.loanId, status: 'disbursed', amount: data.amount };
  }

  private async getLoans(context: ServiceContext): Promise<any> {
    return { loans: [], totalOutstanding: 0, scope: context.scope };
  }

  private async repayLoan(context: ServiceContext, data: any): Promise<any> {
    return {
      loanId: data.loanId,
      paymentAmount: data.amount,
      remainingBalance: 5000,
    };
  }
}

/**
 * Service registry for managing context-aware services
 */
@Injectable()
export class ServiceRegistry {
  private services: Map<string, ContextAwareService> = new Map();

  registerService(name: string, service: ContextAwareService): void {
    this.services.set(name, service);
  }

  getService(name: string): ContextAwareService | undefined {
    return this.services.get(name);
  }

  getAvailableServices(): string[] {
    return Array.from(this.services.keys());
  }

  /**
   * Get services available to user in specific context
   */
  getServicesForContext(context: ServiceContext): string[] {
    const availableServices: string[] = [];

    for (const [serviceName, service] of this.services) {
      const operations = service.getServiceOperations();

      // Check if any operation is available in current scope
      const hasAvailableOperation = Object.values(operations).some(
        (operation) => operation.allowedScopes.includes(context.scope),
      );

      if (hasAvailableOperation) {
        availableServices.push(serviceName);
      }
    }

    return availableServices;
  }
}
