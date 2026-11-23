import { defineConfig } from 'vite';
import { env } from 'node:process';

export default defineConfig({
  server: { host: '127.0.0.1', proxy: { '/api': env.TRACE_API_TARGET ?? 'http://127.0.0.1:8000' } },
});
