import axios from 'axios';
import { readGlobalApiKey } from './utils';
import { withMongoClient, DB_SETTINGS, isMongoDbAvailable } from '../utils/db';

// Test both API key authentication and JWT authentication
async function testCombinedAuth() {
  console.log('Testing combined authentication methods...');

  let globalApiKey = readGlobalApiKey();

  // If the function returned a special marker, we need to fetch from DB
  if (globalApiKey === 'db_key_found' && (global as any).__api_key) {
    // Get the full key object from the global variable
    const keyObj = (global as any).__api_key;
    // In a real scenario, we would get the unhashed key, but for this test
    // we'll just use a placeholder since we can't recover the unhashed key
    console.log('Using API key from database:', keyObj.name);
    globalApiKey = 'dummy_key_for_testing';
  } else if (!globalApiKey) {
    // If no key was found, try to fetch directly from the database
    console.log('Attempting to find API key in database...');

    // Check if MongoDB is available
    const dbAvailable = await isMongoDbAvailable();
    if (!dbAvailable) {
      console.error('\n🛑 MongoDB server is not available!');
      console.error(
        'Make sure MongoDB is running on localhost:27017 or use docker-compose.',
      );
      return;
    }

    try {
      await withMongoClient(async (client) => {
        const db = client.db(DB_SETTINGS.DB_NAME);
        const collection = db.collection(DB_SETTINGS.COLLECTIONS.APIKEYS);

        // Look for any active API key
        const key = await collection.findOne({
          revoked: false,
          expiresAt: { $gt: new Date() },
        });

        if (key) {
          console.log(`Found API key in database: ${key.name}`);
          // For demo purposes, we'll print that we found a key
          globalApiKey = 'dummy_key_for_testing';
        } else {
          console.error(
            'No valid API keys found in database. Please run "bun apikey:generate" first.',
          );
          return;
        }
      });
    } catch (error) {
      console.error('Error accessing database:', error);
      console.error(
        'No global API key found. Please run "bun apikey:generate" first.',
      );
      return;
    }
  }

  // Skip the actual test if we're using a dummy key (key from DB that we can't decrypt)
  if (globalApiKey === 'dummy_key_for_testing') {
    console.log(
      '\n⚠️ Found an API key in the database but cannot use the actual key value for testing.',
    );
    console.log(
      'To run a real test, use "bun apikey:generate" to create a new key and update env files.',
    );
    return;
  }

  console.log(`Found API key: ${globalApiKey.substring(0, 16)}...`);

  try {
    // First, try the public endpoint
    console.log(
      '\nTesting public health endpoint (no authentication required)...',
    );
    try {
      const publicResponse = await axios.get(
        'http://localhost:4000/v1/health/public',
      );
      console.log(`Public Health Endpoint Status: ${publicResponse.status}`);
      console.log(`Public Health Endpoint Response:`, publicResponse.data);
      console.log('✅ Public endpoint accessible');
    } catch (publicError) {
      console.error('Public health endpoint failed:', publicError.message);
      if (publicError.response) {
        console.error('Response status:', publicError.response.status);
        console.error('Response data:', publicError.response.data);
      }
      console.log(
        '⚠️ Public health endpoint is not accessible, but will continue with authenticated test',
      );
    }

    // Test with API key
    console.log('\nTesting with API key authentication:');
    const apiKeyResponse = await axios.get('http://localhost:4000/v1/health', {
      headers: {
        'x-api-key': globalApiKey,
      },
    });

    console.log(`API Key Auth Status: ${apiKeyResponse.status}`);
    console.log(`API Key Auth Response:`, apiKeyResponse.data);
    console.log('🎉 API key authentication successful!');

    // Get a JWT token for testing (this is just for demonstration)
    console.log('\nObtaining a JWT token for testing...');
    console.log(
      'Note: In a real application, you would log in to get this token',
    );
    // In a real test, you would log in and get a real token
    const dummyToken =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiMTIzIiwicm9sZXMiOlsiVVNFUiJdfSwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE2MTcwMjM5MTksImlzcyI6ImJpdHNhY2NvIn0.dummy_token';

    try {
      // Test with JWT token (likely to fail with dummy token)
      console.log('\nTesting with JWT authentication:');
      const jwtResponse = await axios.get('http://localhost:4000/v1/health', {
        headers: {
          Authorization: `Bearer ${dummyToken}`,
        },
      });

      console.log(`JWT Auth Status: ${jwtResponse.status}`);
      console.log(`JWT Auth Response:`, jwtResponse.data);
      console.log('🎉 JWT authentication successful!');
    } catch (error) {
      console.error(
        'JWT authentication failed (expected with dummy token):',
        error.message,
      );
      console.log(
        'This error is expected with the dummy token. In a real test, you would use a valid JWT token.',
      );
    }

    console.log('\nCombined auth testing complete!');
  } catch (error) {
    console.error('Authentication testing failed:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    }
  }
}

// Run the test
testCombinedAuth().catch(console.error);
