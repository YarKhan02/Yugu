// A fixture for SessionTerminating detection. AuthSelect is the auth middleware:
// it SELECTs the sessions table to authenticate the request. LogoutDelete is a
// handler that DELETEs that same table — session termination. LoginInsert and
// ReadWidgets are controls: an INSERT into the auth table and an unrelated read
// must not be mistaken for termination.
package main

import (
	"context"
	"database/sql"
)

var db *sql.DB

// AuthSelect stands in for auth middleware: it reads the credential store.
func AuthSelect(ctx context.Context, token string) {
	_ = db.QueryRowContext(ctx, "SELECT user_id FROM sessions WHERE token = $1", token)
}

// LogoutDelete revokes the credential the auth path reads.
func LogoutDelete(ctx context.Context, token string) {
	_, _ = db.ExecContext(ctx, "DELETE FROM sessions WHERE token = $1", token)
}

// LoginInsert writes the auth table but creates a session, not ends one.
func LoginInsert(ctx context.Context, uid int64, token string) {
	_, _ = db.ExecContext(ctx, "INSERT INTO sessions (user_id, token) VALUES ($1, $2)", uid, token)
}

// ReadWidgets touches an unrelated table.
func ReadWidgets(ctx context.Context) {
	_, _ = db.QueryContext(ctx, "SELECT id FROM widgets")
}

func main() {
	ctx := context.Background()
	AuthSelect(ctx, "t")
	LogoutDelete(ctx, "t")
	LoginInsert(ctx, 1, "t")
	ReadWidgets(ctx)
}
