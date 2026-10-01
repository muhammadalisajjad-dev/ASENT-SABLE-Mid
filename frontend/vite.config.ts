import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  resolve: {
    preserveSymlinks: true,
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    fs: {
      strict: false,
      allow: [
        'C:/Users/Administrator/Desktop/Working POC',
        'C:/Working_POC',
        'E:/Working_POC',
      ]
    },
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/invoicehub': 'http://127.0.0.1:8000'
    }
  },
  preview: {
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/invoicehub': 'http://127.0.0.1:8000'
    }
  }
});
