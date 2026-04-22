// full_server demonstrates how to wire together every Velocity subsystem into
// a single production-ready server that exposes:
//
//   - S3-compatible API (SigV4 auth, buckets, objects, multipart, versioning)
//   - Enterprise REST API (IAM, metrics, lifecycle, integrity, cluster)
//   - Admin UI + JWT-protected general-purpose REST API
//   - Prometheus metrics endpoint
//
// Run:
//
//	cd examples && go run ./full_server
//
// Then use the AWS CLI or curl to interact with it (see USAGE.md for details).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/web"
)

// ---------------------------------------------------------------------------
// Adapter wrappers: bridge the concrete Velocity types to the interfaces
// expected by web.EnterpriseAPI.
// ---------------------------------------------------------------------------

// metricsAdapter adapts velocity.MetricsCollector to the web.MetricsRenderer interface.
type metricsAdapter struct {
	mc *velocity.MetricsCollector
}

func (a *metricsAdapter) RenderMetrics() (string, error) {
	return a.mc.RenderMetrics(), nil
}

// notificationAdapter adapts velocity.NotificationManager to the web.NotificationService interface.
type notificationAdapter struct {
	nm *velocity.NotificationManager
}

func (a *notificationAdapter) PutBucketNotification(bucket string, config any) error {
	cfg, ok := config.(velocity.NotificationConfig)
	if !ok {
		return fmt.Errorf("invalid notification config type")
	}
	return a.nm.PutBucketNotification(bucket, cfg)
}

func (a *notificationAdapter) GetBucketNotification(bucket string) (any, error) {
	return a.nm.GetBucketNotification(bucket), nil
}

func (a *notificationAdapter) DeleteBucketNotification(bucket string) error {
	configs := a.nm.GetBucketNotification(bucket)
	for _, c := range configs {
		if err := a.nm.DeleteBucketNotification(bucket, c.ID); err != nil {
			return err
		}
	}
	return nil
}

// lifecycleAdapter adapts velocity.StorageTierManager to the web.LifecycleService interface.
type lifecycleAdapter struct {
	stm *velocity.StorageTierManager
}

func (a *lifecycleAdapter) PutBucketLifecycle(bucket string, config any) error {
	cfg, ok := config.(*velocity.LifecycleConfig)
	if !ok {
		return fmt.Errorf("invalid lifecycle config type")
	}
	return a.stm.PutBucketLifecycle(bucket, cfg)
}

func (a *lifecycleAdapter) GetBucketLifecycle(bucket string) (any, error) {
	return a.stm.GetBucketLifecycle(bucket)
}

func (a *lifecycleAdapter) DeleteBucketLifecycle(bucket string) error {
	return a.stm.DeleteBucketLifecycle(bucket)
}

func main() {
	dataDir := "./velocity_data"
	httpPort := "9000"
	usersDBPath := "./users.db"

	// Allow overriding via environment variables.
	if v := os.Getenv("VELOCITY_DATA_DIR"); v != "" {
		dataDir = v
	}
	if v := os.Getenv("VELOCITY_PORT"); v != "" {
		httpPort = v
	}
	if v := os.Getenv("VELOCITY_USERS_DB"); v != "" {
		usersDBPath = v
	}

	// --- 1. Open the core database -----------------------------------------
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data dir: %v", err)
	}

	db, err := velocity.New(dataDir)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	db.SetCacheMode("balanced")
	log.Println("Database opened at", dataDir)

	// --- 2. S3 credential store + auth layer --------------------------------
	credStore := velocity.NewS3CredentialStore(db)

	// Generate an admin credential (returns auto-generated access key & secret).
	adminCred, err := credStore.GenerateCredentials("admin", "Default admin credential")
	if err != nil {
		log.Fatalf("Failed to generate S3 credential: %v", err)
	}
	log.Printf("S3 credential generated (access key: %s)", adminCred.AccessKeyID)

	region := "us-east-1"
	sigv4 := velocity.NewSigV4Auth(credStore, region)

	// --- 3. Bucket & multipart managers ------------------------------------
	bucketMgr := velocity.NewBucketManager(db)
	multipartMgr := velocity.NewMultipartManager(db)

	// --- 4. Presigned URL generator ----------------------------------------
	endpoint := "http://localhost:" + httpPort
	presignedGen := velocity.NewPresignedURLGenerator(credStore, region, endpoint)

	// --- 5. IAM policy engine ----------------------------------------------
	iamEngine := velocity.NewIAMPolicyEngine(db)

	// Create a sample admin policy.
	adminPolicy := &velocity.IAMPolicy{
		Name:    "AdminFullAccess",
		Version: "2012-10-17",
		Statements: []velocity.IAMStatement{
			{
				Effect:   "Allow",
				Action:   []string{"s3:*"},
				Resource: []string{"arn:aws:s3:::*"},
			},
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = iamEngine.CreatePolicy(adminPolicy)
	_ = iamEngine.AttachUserPolicy("admin", "AdminFullAccess")
	log.Println("IAM policy engine initialised (AdminFullAccess policy attached to admin)")

	// --- 6. Metrics collector -----------------------------------------------
	metrics := velocity.NewMetricsCollector()

	// --- 7. Storage tier / lifecycle manager --------------------------------
	tierMgr := velocity.NewStorageTierManager(db, 24*time.Hour)

	// --- 8. Notification manager -------------------------------------------
	notifMgr := velocity.NewNotificationManager(db)
	notifMgr.Start(context.Background())
	defer notifMgr.Stop()

	// --- 9. Integrity manager -----------------------------------------------
	integrityMgr := velocity.NewIntegrityManager(db, velocity.IntegrityConfig{
		ErasureEnabled: true,
		DataShards:     4,
		ParityShards:   2,
		BitRotEnabled:  true,
		ScanInterval:   24 * time.Hour,
		HealingEnabled: true,
		HealInterval:   1 * time.Hour,
	})
	if err := integrityMgr.Start(context.Background()); err != nil {
		log.Printf("Integrity manager start warning: %v", err)
	}
	defer integrityMgr.Stop()

	// --- 10. User database (SQLite, for JWT auth) ---------------------------
	userDB, err := web.NewSQLiteUserStorage(usersDBPath)
	if err != nil {
		log.Fatalf("Failed to init user DB: %v", err)
	}
	defer userDB.Close()

	// Bootstrap an admin user if none exists.
	ctx := context.Background()
	if _, err := userDB.GetUserByUsername(ctx, "admin"); err != nil {
		if err := userDB.CreateUser(ctx, &web.User{
			Username: "admin",
			Email:    "admin@localhost",
			Password: "password123",
			Role:     "admin",
		}); err != nil {
			log.Fatalf("Failed to create admin user: %v", err)
		}
		log.Println("Bootstrap admin user created (admin / password123)")
	}

	// --- 11. Build the HTTP server (JWT REST + admin UI) --------------------
	httpServer := web.NewHTTPServer(db, httpPort, userDB)

	// --- 12. Register the S3 API routes ------------------------------------
	s3api := web.NewS3API(db, bucketMgr, multipartMgr, sigv4, presignedGen)
	s3api.RegisterRoutes(httpServer.App())

	// --- 13. Register the Enterprise API routes ----------------------------
	enterpriseAPI := web.NewEnterpriseAPI(
		iamEngine,
		nil, // OIDC provider (nil = disabled)
		nil, // LDAP provider (nil = disabled)
		nil, // STS service (nil = disabled)
		&metricsAdapter{mc: metrics},
		&notificationAdapter{nm: notifMgr},
		&lifecycleAdapter{stm: tierMgr},
		integrityMgr,
		nil, // ClusterManager (nil for single-node)
	)
	enterpriseAPI.RegisterRoutes(httpServer.App())

	// --- 14. Start a background metrics refresh loop -----------------------
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			metrics.UpdateGauges(db, nil, nil, integrityMgr)
		}
	}()

	// --- 15. Start the server ----------------------------------------------
	log.Printf("=== Velocity Server starting on port %s ===", httpPort)
	log.Printf("  Admin UI:      http://localhost:%s/admin-ui", httpPort)
	log.Printf("  S3 API:        http://localhost:%s/s3/", httpPort)
	log.Printf("  Enterprise:    http://localhost:%s/api/v1/", httpPort)
	log.Printf("  REST API:      http://localhost:%s/api/", httpPort)
	log.Printf("  Metrics:       http://localhost:%s/api/v1/metrics", httpPort)
	log.Printf("  JWT login:     POST http://localhost:%s/auth/login", httpPort)
	log.Println()
	log.Println("AWS CLI config:")
	log.Println("  aws configure")
	log.Printf("  AWS Access Key ID:     %s", adminCred.AccessKeyID)
	log.Printf("  AWS Secret Access Key: %s", adminCred.SecretAccessKey)
	log.Printf("  Default region:        %s", region)
	log.Println()
	log.Printf("Example: aws --endpoint-url %s s3 mb s3://my-bucket", endpoint)

	go func() {
		if err := httpServer.Start(); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// --- 16. Wait for shutdown signal --------------------------------------
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	_ = httpServer.Stop()
	log.Println("Server stopped.")
}
