// Package store owns the authoritative SQLite connection. No other production
// package may import database/sql or the SQLite driver directly.
package store

import _ "github.com/ncruces/go-sqlite3/driver"

const sqliteDriverName = "sqlite3"
