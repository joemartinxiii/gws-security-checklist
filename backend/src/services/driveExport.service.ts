import { WorkspaceService } from './workspace.service';

/**
 * Minimal Drive helper for checklist CSV export. Not a full Drive admin surface.
 */
export class DriveExportService extends WorkspaceService {
  async uploadFile(
    userEmail: string,
    fileName: string,
    fileContent: string | Buffer,
    mimeType: string = 'text/csv'
  ): Promise<{ id: string; webViewLink: string }> {
    const drive = await this.driveFor(userEmail);

    // drive.file can create a file the app owns. It cannot place that file in
    // an arbitrary existing folder, so callers do not pass a parent id.
    const fileMetadata: { name: string } = {
      name: fileName,
    };

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
