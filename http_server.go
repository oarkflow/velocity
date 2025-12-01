package velocity

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang-jwt/jwt/v5"
)

// HTTPServer represents an HTTP server for the Velocity database
type HTTPServer struct {
	db     *DB
	app    *fiber.App
	port   string
	userDB UserStorage
}

// NewHTTPServer creates a new HTTP server
func NewHTTPServer(db *DB, port string, userDB UserStorage) *HTTPServer {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	// Security middleware
	app.Use(helmet.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,DELETE",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))
	app.Use(recover.New())
	app.Use(logger.New())

	// Rate limiting
	app.Use(limiter.New(limiter.Config{
		Max:        100,             // max requests per window
		Expiration: 1 * time.Minute, // per minute
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP() // limit by IP
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many requests",
			})
		},
	}))

	server := &HTTPServer{
		db:     db,
		app:    app,
		port:   port,
		userDB: userDB,
	}

	server.setupRoutes()
	return server
}

func (s *HTTPServer) setupRoutes() {
	// Public routes
	s.app.Post("/auth/login", s.handleLogin)

	// Protected API routes
	api := s.app.Group("/api", s.jwtAuthMiddleware())

	api.Post("/put", s.handlePut)
	api.Get("/get/:key", s.handleGet)
	api.Delete("/delete/:key", s.handleDelete)

	api.Post("/files", s.handleFileUpload)
	api.Get("/files", s.handleFileList)
	api.Get("/files/:key/meta", s.handleFileMetadata)
	api.Get("/files/:key", s.handleFileDownload)
	api.Delete("/files/:key", s.handleFileDelete)
}

// jwtAuthMiddleware validates JWT tokens
func (s *HTTPServer) jwtAuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing authorization header",
			})
		}

		// Extract token from "Bearer <token>"
		const bearerPrefix = "Bearer "
		if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid authorization header format",
			})
		}
		tokenString := authHeader[len(bearerPrefix):]

		// Parse and validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.NewError(fiber.StatusUnauthorized, "Unexpected signing method")
			}
			return []byte("your-secret-key-change-this-in-production"), nil // TODO: Make configurable
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}

		// Extract claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Locals("username", claims["username"])
		}

		return c.Next()
	}
}

// handleLogin authenticates users and returns JWT token
func (s *HTTPServer) handleLogin(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid JSON",
		})
	}

	// Authenticate user using user storage
	user, err := s.userDB.AuthenticateUser(c.Context(), req.Username, req.Password)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"role":     user.Role,
		"tenant":   user.Tenant,
		"exp":      time.Now().Add(24 * time.Hour).Unix(), // Token expires in 24 hours
		"iat":      time.Now().Unix(),
	})

	tokenString, err := token.SignedString([]byte("your-secret-key-change-this-in-production"))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate token",
		})
	}

	return c.JSON(fiber.Map{
		"token":      tokenString,
		"expires_in": 86400, // 24 hours in seconds
		"user": fiber.Map{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
			"tenant":   user.Tenant,
		},
	})
}

func (s *HTTPServer) handlePut(c *fiber.Ctx) error {
	var req struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid JSON")
	}

	if req.Key == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Key is required")
	}

	err := s.db.Put([]byte(req.Key), []byte(req.Value))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"status": "ok",
	})
}

func (s *HTTPServer) handleGet(c *fiber.Ctx) error {
	key := c.Params("key")
	if key == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Key is required")
	}

	value, err := s.db.Get([]byte(key))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Key not found")
	}

	return c.JSON(fiber.Map{
		"key":   key,
		"value": string(value),
	})
}

func (s *HTTPServer) handleDelete(c *fiber.Ctx) error {
	key := c.Params("key")
	if key == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Key is required")
	}

	err := s.db.Delete([]byte(key))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"status": "ok",
	})
}

func (s *HTTPServer) handleFileUpload(c *fiber.Ctx) error {
	fileHeader, err := c.FormFile("file")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "File is required")
	}

	file, err := fileHeader.Open()
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Unable to open uploaded file")
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Unable to read uploaded file")
	}

	key := c.FormValue("key")
	overwrite := c.QueryBool("overwrite", false)

	if overwrite && key != "" && s.db.HasFile(key) {
		if err := s.db.DeleteFile(key); err != nil && !errors.Is(err, ErrFileNotFound) {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
	}

	contentType := fileHeader.Header.Get("Content-Type")
	if contentType == "" && len(data) > 0 {
		contentType = http.DetectContentType(data)
	}

	meta, err := s.db.StoreFile(key, fileHeader.Filename, contentType, data)
	if err != nil {
		if errors.Is(err, ErrFileExists) {
			return fiber.NewError(fiber.StatusConflict, "File already exists. Provide overwrite=true to replace it.")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status": "stored",
		"file":   meta,
	})
}

func (s *HTTPServer) handleFileDownload(c *fiber.Ctx) error {
	key := c.Params("key")
	if key == "" {
		return fiber.NewError(fiber.StatusBadRequest, "File key is required")
	}

	data, meta, err := s.db.GetFile(key)
	if err != nil {
		if errors.Is(err, ErrFileNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "File not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	if meta.ContentType != "" {
		c.Set(fiber.HeaderContentType, meta.ContentType)
	}
	c.Set(fiber.HeaderContentLength, strconv.FormatInt(meta.Size, 10))
	c.Attachment(meta.Filename)

	return c.SendStream(bytes.NewReader(data))
}

func (s *HTTPServer) handleFileMetadata(c *fiber.Ctx) error {
	key := c.Params("key")
	if key == "" {
		return fiber.NewError(fiber.StatusBadRequest, "File key is required")
	}

	meta, err := s.db.GetFileMetadata(key)
	if err != nil {
		if errors.Is(err, ErrFileNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "File not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"file": meta,
	})
}

func (s *HTTPServer) handleFileList(c *fiber.Ctx) error {
	files, err := s.db.ListFiles()
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"files": files,
	})
}

func (s *HTTPServer) handleFileDelete(c *fiber.Ctx) error {
	key := c.Params("key")
	if key == "" {
		return fiber.NewError(fiber.StatusBadRequest, "File key is required")
	}

	if err := s.db.DeleteFile(key); err != nil {
		if errors.Is(err, ErrFileNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "File not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"status": "deleted",
	})
}

// Start starts the HTTP server
func (s *HTTPServer) Start() error {
	log.Printf("Starting HTTP server on port %s", s.port)
	return s.app.Listen(":" + s.port)
}

// Stop stops the HTTP server
func (s *HTTPServer) Stop() error {
	return s.app.Shutdown()
}
