// Package migrations embeds the gateway's SQL migrations, applied in file-name order.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
