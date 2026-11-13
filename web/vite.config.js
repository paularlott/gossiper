// Builds web/dist, which the Go binary embeds (web/embed.go): the OpenAPI document (/api/openapi.json) and the API
// reference (/api-docs/). Everything is bundled from node_modules; the page loads nothing from a CDN, so the server
// works on a network without internet access.
import { defineConfig } from 'vite'
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { gzipSync } from 'node:zlib'
import { resolve } from 'node:path'

const here = import.meta.dirname

// emptyOutDir clears web/dist, including the committed placeholder that lets the Go packages compile before a build.
const keepPlaceholder = {
  name: 'keep-dist-placeholder',
  writeBundle(opts) { writeFileSync(resolve(opts.dir, '.gitkeep'), '') },
}

// Redoc's standalone bundle carries React, DOMPurify and the rest inside it, so build.license lists Redoc alone, and
// the minifier drops the packages' notices (/*! ... */ and /** @license ... */ comments). Their notices are added to licenses.md from the
// bundle as Redoc ships it.
const redocNotices = {
  name: 'redoc-notices',
  writeBundle(opts) {
    const bundle = readFileSync(resolve(here, 'node_modules/redoc/bundles/redoc.standalone.js'), 'utf8')
    const notices = [...new Set((bundle.match(/\/\*[*!][\s\S]*?\*\//g) || [])
      .map((c) => c.slice(3, -2).replace(/^\s*\* ?/gm, '').trim())
      .filter((c) => /@license|copyright/i.test(c)))]
    if (notices.length === 0) throw new Error('redoc-notices: no notices found in Redoc\'s bundle')
    const file = resolve(opts.dir, 'licenses.md')
    writeFileSync(file, readFileSync(file, 'utf8') + '\n## Packages bundled in redoc.standalone.js\n\n' +
      notices.map((n) => '```\n' + n + '\n```\n').join('\n'))
  },
}

// The binary embeds the scripts and stylesheets gzipped (Redoc is 2.3 MB, 0.7 MB gzipped): the server sends them as
// they are to clients that accept gzip (all browsers) and decompresses them for any other.
const gzipAssets = {
  name: 'gzip-assets',
  writeBundle(opts) {
    const dir = resolve(opts.dir, 'assets')
    for (const name of readdirSync(dir)) {
      if (!/\.(js|css)$/.test(name)) continue
      writeFileSync(resolve(dir, name + '.gz'), gzipSync(readFileSync(resolve(dir, name)), { level: 9 }))
      rmSync(resolve(dir, name))
    }
  },
}

// Redoc's "API docs by Redocly" badge loads the Redocly logo from cdn.redoc.ly. The skin (src/api-docs.css) hides the
// badge, but a hidden image is still fetched, so point it at a blank one. Its icon sets are fetched from
// cdn.redocly.com by joining a base URL and an icon's name: an empty data: URL as the base makes any such URL inline
// data, fetched from nowhere. So the API reference makes no outside request. The build fails if Redoc changes any of
// this, so the plugin is reviewed on a Redoc upgrade.
const blank = 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>')
const redocURLs = {
  'https://cdn.redoc.ly/redoc/logo-mini-full.svg': blank,
  'https://cdn.redoc.ly/redoc/logo-mini.svg': blank,
  'https://cdn.redocly.com/icons/fa/7.0.0': 'data:,',
  'https://cdn.redocly.com/icons/code/5.24.0': 'data:,',
  // the telemetry collector (switched off in src/api-docs.js, and the CSP's connect-src blocks it): nowhere to send to
  'https://otel.cloud.redocly.com/v1/traces': 'data:,',
}
const redocOffline = {
  name: 'redoc-offline',
  transform(code, id) {
    if (!id.includes('/node_modules/redoc/bundles/')) return
    let out = code
    for (const [url, local] of Object.entries(redocURLs)) {
      if (!out.includes(url)) this.error(`redoc no longer references ${url}: review the redoc-offline plugin`)
      out = out.replaceAll(url, local)
    }
    return { code: out, map: null }
  },
}

// dist/openapi.json, served at /api/openapi.json: Redocly CLI bundles the description (openapi/openapi.yaml and any
// file it references) into one JSON document.
const openapiYaml = resolve(here, 'openapi/openapi.yaml')
const openapiJson = {
  name: 'openapi-json',
  buildStart() { this.addWatchFile(openapiYaml) },
  generateBundle() {
    const redocly = resolve(here, 'node_modules/.bin/redocly')
    const json = execFileSync(redocly, ['bundle', openapiYaml, '--ext', 'json'], {
      cwd: here, encoding: 'utf8', maxBuffer: 64 << 20, stdio: ['ignore', 'pipe', 'inherit'],
      env: { ...process.env, REDOCLY_TELEMETRY: 'off', REDOCLY_SUPPRESS_UPDATE_NOTICE: 'true' },
    })
    this.emitFile({ type: 'asset', fileName: 'openapi.json', source: JSON.stringify(JSON.parse(json)) })
  },
}

export default defineConfig({
  root: here,
  base: '/api-docs/',
  publicDir: false,
  plugins: [redocOffline, openapiJson, redocNotices, gzipAssets, keepPlaceholder],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    modulePreload: false,
    chunkSizeWarningLimit: 4096, // the API reference bundles Redoc (about 2 MB)
    // The licences of the bundled packages (Redoc, React and theirs), for the release's THIRD_PARTY_LICENSES.txt.
    license: { fileName: 'licenses.md' },
    rolldownOptions: {
      input: { 'api-docs': resolve(here, 'api-docs/index.html') },
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
})
