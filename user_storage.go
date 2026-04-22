package velocity

import "context"

// UserStorage defines minimal interface needed by TCPServer/HTTP handlers.
// Kept intentionally minimal to avoid import cycles with the web package.
type UserStorage interface {
	AuthenticateUser(ctx context.Context, username, password string) (any, error)
}
