import { defineConfig, mergeConfig } from 'vite'
import appConfig from '../vite.config'

export default mergeConfig(appConfig, defineConfig({
  server: {
    host: '127.0.0.1',
    port: 14173,
    strictPort: true,
    proxy: { '/api': 'http://127.0.0.1:18080' },
  },
}))
