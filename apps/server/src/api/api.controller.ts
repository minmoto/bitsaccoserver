import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ApiService } from './api.service';

@ApiTags('health')
@Controller()
export class ApiController {
  constructor(private readonly appService: ApiService) {}

  @Get()
  @ApiOperation({ summary: 'API information' })
  @ApiResponse({ status: 200, description: 'API information' })
  getInfo(): object {
    return this.appService.getInfo();
  }

  @Get('health')
  @ApiOperation({ summary: 'Health check endpoint' })
  @ApiResponse({ status: 200, description: 'Service is healthy' })
  getHealth(): object {
    return this.appService.getHealth();
  }
}
