import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
export default defineConfig({ plugins: [vue()], server: { proxy: { '/api': 'http://127.0.0.1:7410', '/healthz': 'http://127.0.0.1:7410' } }, build: { target: 'es2022', sourcemap: true } })
