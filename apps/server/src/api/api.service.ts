import { Injectable } from '@nestjs/common';

@Injectable()
export class ApiService {
  getHealth(): object {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'bitsaccoserver-bitsaccoserver',
      version: '1.0.0',
    };
  }

  getInfo(): object {
    return {
      name: 'Bitsaccoserver API',
      description:
        'Multi-tenant API management platform with organization management, API key lifecycle, and integrated services',
      version: '1.0.0',
      documentation: '/api/docs',
      features: [
        'Organization Management',
        'API Key Lifecycle Management',
        'Role-based Access Control',
        'Usage Tracking & Analytics',
        'Integrated Currency Swap (KES ↔ BTC)',
        'Real-time Rate Limiting',
        'Unified Authentication (JWT + API Keys)',
      ],
      endpoints: {
        health: '/api/v1/health',
        auth: '/api/v1/auth',
        profile: '/api/v1/profile',
        organizations: '/api/v1/organizations',
        'api-keys': '/api/v1/organizations/{orgId}/api-keys',
      },
    };
  }
}
