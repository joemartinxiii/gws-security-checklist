export interface GCPConfig {
  projectId: string;
  region: string;
}

export function getGCPConfig(): GCPConfig {
  return {
    projectId: process.env.GCP_PROJECT_ID || '',
    region: process.env.GCP_REGION || 'us-central1',
  };
}
