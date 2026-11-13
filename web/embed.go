// Package webassets embeds the admin API's description and reference page, and the status page, into the binary.
package webassets

import "embed"

// Dist holds the web build output (openapi.json, api-docs/ and ui/ with their assets), produced by `npm run build` in
// web/ (task webassets). Before a build it holds only a placeholder, and the server answers 404 for the pages.
//
//go:embed all:dist
var Dist embed.FS
