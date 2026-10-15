import dotenv from 'dotenv';
import path from 'path';

/**
 * Load env before any module reads JWT_SECRET at import time.
 * `npm run dev` from the repo root looks at backend/.env.
 * `npm run dev` from backend/ looks at ./.env.
 * Existing process env wins, so `dotenv -e` still overrides the file.
 */
dotenv.config({ path: path.resolve(process.cwd(), 'backend/.env') });
dotenv.config({ path: path.resolve(process.cwd(), '.env') });
