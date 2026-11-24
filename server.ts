import http from 'node:http';
import dotenv from 'dotenv';
import { createApp } from './server/app.ts';
import { loadOrCreateSessionSecret } from './server/crypto.ts';
import { startScheduler, stopScheduler } from './server/scheduler.ts';
import { validateRuntimeConfiguration } from './server/security.ts';

dotenv.config();

const PORT = Number(process.env.PORT || 3000);

async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';
  const sessionSecret = loadOrCreateSessionSecret();
  const validation = validateRuntimeConfiguration({ isProd, sessionSecret });

  for (const warn of validation.warnings) {
    console.warn(`[config warning] ${warn}`);
  }
  if (!validation.ok) {
    for (const err of validation.errors) {
      console.error(`[config error] ${err}`);
    }
    throw new Error(`Runtime configuration validation failed: ${validation.errors.join(' | ')}`);
  }

  const httpServer = http.createServer();
  const app = await createApp({ isProd, httpServer });
  httpServer.on('request', app);

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Privacy Monitor running at http://0.0.0.0:${PORT}`);
    startScheduler();
  });

  const shutdown = () => {
    stopScheduler();
    httpServer.close(() => {
      process.exit(0);
    });
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
