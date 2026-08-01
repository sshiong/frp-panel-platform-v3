import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: { proxy: { '/api': 'http://127.0.0.1:7400', '/healthz': 'http://127.0.0.1:7400' } },
  build: { target: 'es2022', sourcemap: true }
})
