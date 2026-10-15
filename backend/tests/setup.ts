process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret-for-testing-only';
process.env.GCP_PROJECT_ID = process.env.GCP_PROJECT_ID || 'test-project';
process.env.WORKSPACE_DOMAIN = process.env.WORKSPACE_DOMAIN || 'example.com';
process.env.GWS_ALLOWED_DOMAINS = process.env.GWS_ALLOWED_DOMAINS || 'example.com,subsidiary.com';
process.env.GOOGLE_REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3001/api/auth/callback';
process.env.SERVICE_ACCOUNT_EMAIL =
  process.env.SERVICE_ACCOUNT_EMAIL || 'security-checklist-sa@test-project.iam.gserviceaccount.com';
