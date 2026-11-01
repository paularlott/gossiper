// The API reference at /api-docs/: Redoc 3, bundled from node_modules into the binary, renders the OpenAPI document
// the server serves at /api/openapi.json (built from web/openapi/openapi.yaml). Nothing loads from outside the server.
import { init } from 'redoc/bundles/redoc.standalone.js'
import './api-docs.css'

init('/api/openapi.json', {
  disableTelemetry: true, // Redoc would otherwise report page views to Redocly
  router: 'hash', // the server serves only /api-docs/ itself, so in-page links stay in the fragment
}, document.getElementById('redoc'))
