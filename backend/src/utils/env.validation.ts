function envPresent(key: string): boolean {
  const v = process.env[key];
  return typeof v === 'string' && v.trim().length > 0;
}

const MIN_PRODUCTION_JWT_SECRET_LENGTH = 32;

/** Required variables that are missing, and production-only misconfigurations. */
export function findEnvironmentProblems(): { missing: string[]; invalid: string[] } {
  const isProduction = process.env.NODE_ENV === 'production';

  const required = ['JWT_SECRET', 'GCP_PROJECT_ID', 'WORKSPACE_DOMAIN'];
  // OAuth client credentials are required in production (Secret Manager).
  // Local/dev may still start without them for non-login work, but login will fail.
  // Production also needs the bucket: without it results and sessions land on the
  // container's local disk and vanish between instances.
  // GOOGLE_REDIRECT_URI is not required to start: deploy.sh sets it once the
  // service URL is known, and sign-in refuses to start until then.
  if (isProduction) {
    required.push('GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'CHECKLIST_BUCKET');
  }

  const missing = required.filter((key) => !envPresent(key));
  const invalid: string[] = [];

  if (isProduction) {
    for (const key of [...required, 'GOOGLE_REDIRECT_URI']) {
      if (envPresent(key) && /placeholder/i.test(process.env[key] as string)) {
        invalid.push(`${key} still contains a PLACEHOLDER value`);
      }
    }
    const secret = process.env.JWT_SECRET || '';
    if (envPresent('JWT_SECRET') && secret.length < MIN_PRODUCTION_JWT_SECRET_LENGTH) {
      invalid.push(`JWT_SECRET must be at least ${MIN_PRODUCTION_JWT_SECRET_LENGTH} characters`);
    }
  }

  return { missing, invalid };
}

export function validateEnvironment(): void {
  const isProduction = process.env.NODE_ENV === 'production';
  const { missing, invalid } = findEnvironmentProblems();

  if (missing.length > 0 || invalid.length > 0) {
    console.error('❌ CRITICAL: Invalid environment configuration:');
    missing.forEach((key) => console.error(`   - ${key} is missing`));
    invalid.forEach((problem) => console.error(`   - ${problem}`));
    console.error('\nApplication cannot start until these are fixed.');
    console.error('Please check your Secret Manager configuration.');
    process.exit(1);
  }

  // Optional but recommended
  const recommended = ['CORS_ORIGIN', 'GWS_ALLOWED_DOMAINS', 'SERVICE_ACCOUNT_EMAIL', 'GOOGLE_REDIRECT_URI'];
  if (!isProduction) {
    recommended.push('GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET');
  }
  const missingRecommended = recommended.filter((key) => !envPresent(key));

  if (missingRecommended.length > 0) {
    console.warn('⚠️  WARNING: Missing recommended environment variables:');
    missingRecommended.forEach((key) => console.warn(`   - ${key} (will use fallback)`));
  }

  console.log('✅ Environment validation passed');
}
