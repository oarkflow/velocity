package velocity

import (
	"context"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	v2 "github.com/oarkflow/cas"
	"github.com/oarkflow/squealx"
)

// User represents a user in the system
type User struct {
	ID        int       `db:"id" json:"id"`
	Username  string    `db:"username" json:"username"`
	Email     string    `db:"email" json:"email"`
	Password  string    `db:"password" json:"password"` // hashed
	Role      string    `db:"role" json:"role"`
	Tenant    string    `db:"tenant" json:"tenant"`
	Namespace string    `db:"namespace" json:"namespace"`
	Scope     string    `db:"scope" json:"scope"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// UserStorage interface for user management
type UserStorage interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByID(ctx context.Context, id int) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id int) error
	ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
	AuthenticateUser(ctx context.Context, username, password string) (*User, error)
	Authorize(ctx context.Context, principal, tenant, resource, action string) bool
	Close() error
}

// SQLiteUserStorage implements UserStorage with SQLite
type SQLiteUserStorage struct {
	db     *squealx.DB
	auth   *v2.Authorizer
	tenant *v2.Tenant
}

// NewSQLiteUserStorage creates a new SQLite user storage
func NewSQLiteUserStorage(dbPath string) (UserStorage, error) {
	db, err := squealx.Open("sqlite3", dbPath, "user_storage")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables
	if err := setupUserTables(db); err != nil {
		return nil, fmt.Errorf("failed to setup tables: %w", err)
	}

	// Initialize CAS authorizer
	auth := v2.NewAuthorizer(v2.WithDefaultDeny(true))

	// Create default tenant
	tenant := v2.NewTenant("default-company", "default-namespace")
	tenant.AddNamespace("default-namespace")

	// Add default scope
	err = tenant.AddScopeToNamespace("default-namespace", v2.NewScope("default-scope"))
	if err != nil {
		return nil, fmt.Errorf("failed to add default scope: %w", err)
	}

	auth.AddTenant(tenant)

	// Setup default roles and permissions
	if err := setupDefaultRoles(auth); err != nil {
		return nil, fmt.Errorf("failed to setup roles: %w", err)
	}

	storage := &SQLiteUserStorage{
		db:     db,
		auth:   auth,
		tenant: tenant,
	}

	return storage, nil
}

// setupUserTables creates the necessary database tables
func setupUserTables(db *squealx.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		tenant TEXT NOT NULL DEFAULT 'default-company',
		namespace TEXT NOT NULL DEFAULT 'default-namespace',
		scope TEXT NOT NULL DEFAULT 'default-scope',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant);
	`

	_, err := db.NamedExec(schema, nil)
	return err
}

// setupDefaultRoles sets up default roles and permissions
func setupDefaultRoles(auth *v2.Authorizer) error {
	// Admin role - full access
	adminRole := v2.NewRole("admin")
	adminRole.AddPermission(
		v2.NewPermission("velocity", "user", "create"),
		v2.NewPermission("velocity", "user", "read"),
		v2.NewPermission("velocity", "user", "update"),
		v2.NewPermission("velocity", "user", "delete"),
		v2.NewPermission("velocity", "db", "put"),
		v2.NewPermission("velocity", "db", "get"),
		v2.NewPermission("velocity", "db", "delete"),
	)

	// User role - limited access
	userRole := v2.NewRole("user")
	userRole.AddPermission(
		v2.NewPermission("velocity", "db", "put"),
		v2.NewPermission("velocity", "db", "get"),
		v2.NewPermission("velocity", "user", "read"),
	)

	auth.AddRoles(adminRole, userRole)
	return nil
}

// CreateUser creates a new user
func (s *SQLiteUserStorage) CreateUser(ctx context.Context, user *User) error {
	if user.Tenant == "" {
		user.Tenant = "default-company"
	}
	if user.Namespace == "" {
		user.Namespace = "default-namespace"
	}
	if user.Scope == "" {
		user.Scope = "default-scope"
	}
	if user.Role == "" {
		user.Role = "user"
	}

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	query := `
		INSERT INTO users (username, email, password, role, tenant, namespace, scope, created_at, updated_at)
		VALUES (:username, :email, :password, :role, :tenant, :namespace, :scope, :created_at, :updated_at)
	`

	_, err := s.db.NamedExecContext(ctx, query, user)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Add user to CAS
	principalRole := &v2.PrincipalRole{
		Principal: user.Username,
		Tenant:    user.Tenant,
		Namespace: user.Namespace,
		Scope:     user.Scope,
		Role:      user.Role,
	}

	s.auth.AddPrincipalRole(principalRole)

	return nil
}

// GetUserByUsername retrieves a user by username
func (s *SQLiteUserStorage) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	query := `SELECT * FROM users WHERE username = :username LIMIT 1`

	err := s.db.Select(&user, query, map[string]any{
		"username": username,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}
	return &user, nil
}

// GetUserByID retrieves a user by ID
func (s *SQLiteUserStorage) GetUserByID(ctx context.Context, id int) (*User, error) {
	var user User
	query := `SELECT * FROM users WHERE id = :id`
	err := s.db.Select(&user, query, map[string]any{
		"id": id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}
	return &user, nil
}

// UpdateUser updates a user
func (s *SQLiteUserStorage) UpdateUser(ctx context.Context, user *User) error {
	user.UpdatedAt = time.Now()

	query := `
		UPDATE users SET
			username = :username,
			email = :email,
			password = :password,
			role = :role,
			tenant = :tenant,
			namespace = :namespace,
			scope = :scope,
			updated_at = :updated_at
		WHERE id = :id
	`

	result, err := s.db.NamedExecContext(ctx, query, user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// DeleteUser deletes a user
func (s *SQLiteUserStorage) DeleteUser(ctx context.Context, id int) error {
	query := `DELETE FROM users WHERE id = :id`

	result, err := s.db.NamedExecContext(ctx, query, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// ListUsers lists users with pagination
func (s *SQLiteUserStorage) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	var users []*User
	query := `SELECT * FROM users ORDER BY created_at DESC LIMIT :limit OFFSET :offset`
	err := s.db.Select(&users, query, map[string]interface{}{
		"limit":  limit,
		"offset": offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	return users, nil
}

// AuthenticateUser authenticates a user with username and password
func (s *SQLiteUserStorage) AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	user, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	// In a real implementation, you should hash and compare passwords properly
	// For now, we'll do a simple comparison (NOT SECURE FOR PRODUCTION)
	if user.Password != password {
		return nil, fmt.Errorf("invalid password")
	}

	return user, nil
}

// Authorize checks if a principal has permission for a resource and action
func (s *SQLiteUserStorage) Authorize(ctx context.Context, principal, tenant, resource, action string) bool {
	request := v2.Request{
		Principal: principal,
		Tenant:    tenant,
		Resource:  resource,
		Action:    action,
	}

	return s.auth.Authorize(request)
}

// Close closes the database connection
func (s *SQLiteUserStorage) Close() error {
	return s.db.Close()
}
