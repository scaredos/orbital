import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// `npm run dev` proxies the API to a running orchestrator (ORBITAL_URL, default https://localhost:8443).
const target = process.env.ORBITAL_URL ?? 'https://localhost:8443';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: 'dist', emptyOutDir: true, chunkSizeWarningLimit: 1000 },
  server: { proxy: { '/v1': { target, secure: false, ws: true }, '/dl': { target, secure: false } } },
});
