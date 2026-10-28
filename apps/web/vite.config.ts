import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { createHash } from 'node:crypto'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('.', import.meta.url))
function sources(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory()
    ? sources(resolve(directory, entry.name))
    : entry.name.includes('.test.') ? [] : [resolve(directory, entry.name)])
}
const digest = createHash('sha256')
for (const path of [...sources(resolve(root, 'src')), ...['index.html', 'package.json', 'package-lock.json', 'vite.config.ts'].map(file => resolve(root, file))].sort()) {
  digest.update(relative(root, path)).update('\0').update(readFileSync(path)).update('\0')
}
const uiBuild = { schema: 1, locale: 'zh-CN', sourceSha256: digest.digest('hex'), builtAt: new Date().toISOString() }


export default defineConfig({
  define: { __EGRESSDECK_UI_BUILD__: JSON.stringify(uiBuild) },
  plugins: [vue(), {
    name: 'egressdeck-ui-build-identity',
    transformIndexHtml() { return [{ tag: 'meta', attrs: { name: 'egressdeck-ui-build', content: uiBuild.sourceSha256 }, injectTo: 'head' }] },
    generateBundle() { this.emitFile({ type: 'asset', fileName: 'build-info.json', source: JSON.stringify(uiBuild, null, 2) + '\n' }) },
    configureServer(server) {
      server.middlewares.use('/build-info.json', (request, response, next) => {
        if (request.method !== 'GET' && request.method !== 'HEAD') { next(); return }
        response.setHeader('Content-Type', 'application/json; charset=utf-8')
        response.setHeader('Cache-Control', 'no-store')
        response.end(request.method === 'HEAD' ? undefined : JSON.stringify(uiBuild))
      })
    },
  }],
  build: {
    sourcemap: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
})
