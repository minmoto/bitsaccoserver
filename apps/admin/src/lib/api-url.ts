// Define API URL based on environment variable with fallback
export const API_URL =
  process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:4000/v1';
