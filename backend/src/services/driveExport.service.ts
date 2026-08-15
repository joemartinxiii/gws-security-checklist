import { WorkspaceService } from './workspace.service';

/**
 * Minimal Drive helper for checklist CSV export. Not a full Drive admin surface.
 */
export class DriveExportService extends WorkspaceService {
  async uploadFile(
    userEmail: string,
    fileName: string,
    fileContent: string | Buffer,
    mimeType: string = 'text/csv',
    folderId?: string
  ): Promise<{ id: string; webViewLink: string }> {
    const drive = await this.driveFor(userEmail);

    const fileMetadata: { name: string; parents?: string[] } = {
      name: fileName,
    };
    if (folderId) {
      fileMetadata.parents = [folderId];
    }

    const response = await this.withRetry(() =>
      drive.files.create({
        requestBody: fileMetadata,
        media: {
          mimeType,
          body: fileContent,
        },
        fields: 'id, webViewLink',
      })
    );

    return {
      id: response.data.id!,
      webViewLink: response.data.webViewLink || '',
    };
  }
}

export const driveExportService = new DriveExportService();
