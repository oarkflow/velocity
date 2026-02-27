package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/velocity/web"
)

func main() {
	// Initialize User Storage (Argon2id is built-in)
	dbPath := "./users_demo.db"
	storage, err := web.NewSQLiteUserStorage(dbPath)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()

	fmt.Println("=== 🔐 Velocity Security (Argon2id) Demo ===")

	// 1. Create User with Argon2id Hashing
	fmt.Println("\n[1] Registering user 'secure_user' with Argon2id...")
	user := &web.User{
		Username: "secure_user",
		Email:    "security@example.com",
		Password: "very-strong-password-123", // Will be hashed via Argon2id
		Role:     "admin",
	}

	if err := storage.CreateUser(ctx, user); err != nil {
		log.Fatalf("User creation failed: %v", err)
	}
	fmt.Println("User created. Password stored as Argon2id hash.")

	// 2. Authenticate
	fmt.Println("\n[2] Authenticating with correct password...")
	authUser, err := storage.AuthenticateUser(ctx, "secure_user", "very-strong-password-123")
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}
	fmt.Printf("Login success! Authenticated as %s (Role: %s)\n", authUser.Username, authUser.Role)

	// 3. Verify Failed Authentication
	fmt.Println("\n[3] Authenticating with WRONG password...")
	_, err = storage.AuthenticateUser(ctx, "secure_user", "wrong-password")
	if err != nil {
		fmt.Printf("Login failed as expected: %v\n", err)
	}

	fmt.Println("\n=== ✅ Security Demo Completed ===")

	// Cleanup
	_ = os.Remove(dbPath)
}
