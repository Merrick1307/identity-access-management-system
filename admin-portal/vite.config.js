import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { fileURLToPath } from 'url';

var __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig(({ mode }) => {
    const env = loadEnv(mode, process.cwd(), '');

    return {
        plugins: [react()],
        resolve: {
            alias: {
                '@': path.resolve(__dirname, './src'),
            },
        },
        server: {
            port: 3000,
            allowedHosts: ['iam.hexalgon.site', 'localhost', '127.0.0.1', '0.0.0.0'],
            proxy: {
                '/api': {
                    target: env.VITE_API_PROXY_TARGET || 'http://host.docker.internal:8000',
                    changeOrigin: true,
                },
            },
        },
    };
});
