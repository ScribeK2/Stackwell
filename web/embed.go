// Package web holds the built UI. Run `npm run build` in this directory first;
// the committed dist/.gitkeep keeps `go build` working before that.
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
