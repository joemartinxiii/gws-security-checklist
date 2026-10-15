import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { errorHandler, notFoundHandler } from './middleware/error.middleware';
import { requestLogger } from './middleware/request.middleware';
import { requireSameOrigin } from './middleware/origin.middleware';
import authRoutes from './routes/auth.routes';
import hardeningRoutes from './routes/hardening.routes';

/**
 * Express app factory — used by server entrypoint and tests.
 */
export function createApp(): express.Application {
  const app = express();

  app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'", 'https://fonts.gstatic.com'],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
        },
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
      noSniff: true,
      xssFilter: true,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    })
  );

  const corsOrigins = (process.env.CORS_ORIGIN || '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  app.use(
    cors({
      origin: corsOrigins.length > 0 ? corsOrigins : process.env.NODE_ENV === 'production' ? false : true,
      credentials: true,
    })
  );
  app.use(express.json());
  app.use(cookieParser());

  const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 600,
    message: 'Too many requests from this IP, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
  });

  app.use('/api/', generalLimiter);
  app.use('/api', requireSameOrigin);
  app.use(requestLogger);

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  app.use('/api/auth', authRoutes);
  app.use('/api/audit', hardeningRoutes);

  if (process.env.NODE_ENV === 'production' && process.env.SERVE_FRONTEND !== 'false') {
    const staticPath = path.join(__dirname, '../../frontend/dist');
    app.use(express.static(staticPath));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api/')) {
        return next();
      }
      res.sendFile(path.join(staticPath, 'index.html'));
    });
  }

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
