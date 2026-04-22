package web

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity"
)

// TCPServer represents a TCP server for the Velocity database
type TCPServer struct {
	db          *velocity.DB
	port        string
	server      *net.TCPListener
	wg          sync.WaitGroup
	stop        chan struct{}
	userDB      UserStorage
	connections map[*net.TCPConn]*tcpConnection
	connMutex   sync.RWMutex
}

// tcpConnection represents an authenticated TCP connection
type tcpConnection struct {
	authenticated bool
	username      string
	lastActivity  time.Time
}

// NewTCPServer creates a new TCP server
func NewTCPServer(db *velocity.DB, port string, userDB UserStorage) *TCPServer {
	return &TCPServer{
		db:          db,
		port:        port,
		stop:        make(chan struct{}),
		userDB:      userDB,
		connections: make(map[*net.TCPConn]*tcpConnection),
	}
}

// Start starts the TCP server
func (s *TCPServer) Start() error {
	addr, err := net.ResolveTCPAddr("tcp", ":"+s.port)
	if err != nil {
		return err
	}

	server, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	s.server = server

	// Start cleanup routine for inactive connections
	go s.cleanupInactiveConnections()

	go s.acceptLoop()
	return nil
}

func (s *TCPServer) acceptLoop() {
	for {
		select {
		case <-s.stop:
			return
		default:
			conn, err := s.server.AcceptTCP()
			if err != nil {
				continue
			}
			s.wg.Add(1)

			// Register new connection
			s.connMutex.Lock()
			s.connections[conn] = &tcpConnection{
				authenticated: false,
				lastActivity:  time.Now(),
			}
			s.connMutex.Unlock()

			go s.handleConnection(conn)
		}
	}
}

func (s *TCPServer) cleanupInactiveConnections() {
	ticker := time.NewTicker(5 * time.Minute) // Check every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.connMutex.Lock()
			now := time.Now()
			for conn, connInfo := range s.connections {
				// Close connections inactive for more than 30 minutes
				if now.Sub(connInfo.lastActivity) > 30*time.Minute {
					conn.Close()
					delete(s.connections, conn)
				}
			}
			s.connMutex.Unlock()
		}
	}
}

func (s *TCPServer) handleConnection(conn *net.TCPConn) {
	defer s.wg.Done()
	defer func() {
		s.connMutex.Lock()
		delete(s.connections, conn)
		s.connMutex.Unlock()
		conn.Close()
	}()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Update last activity
		s.connMutex.Lock()
		if connInfo, exists := s.connections[conn]; exists {
			connInfo.lastActivity = time.Now()
		}
		s.connMutex.Unlock()

		response := s.processCommand(conn, line)
		conn.Write([]byte(response + "\n"))
	}
}

func (s *TCPServer) processCommand(conn *net.TCPConn, cmd string) string {
	parts := strings.SplitN(cmd, " ", 3)
	if len(parts) == 0 {
		return "ERROR: Invalid command"
	}

	command := strings.ToUpper(parts[0])

	// Check if connection is authenticated for non-AUTH commands
	s.connMutex.RLock()
	connInfo, exists := s.connections[conn]
	s.connMutex.RUnlock()

	if !exists {
		return "ERROR: Connection not registered"
	}

	// AUTH command doesn't require authentication
	if command != "AUTH" && !connInfo.authenticated {
		return "ERROR: Authentication required. Use AUTH username password"
	}

	switch command {
	case "AUTH":
		if len(parts) < 3 {
			return "ERROR: AUTH requires username and password"
		}
		username := parts[1]
		password := parts[2]

		// Authenticate using user storage
		_, err := s.userDB.AuthenticateUser(context.Background(), username, password)
		if err != nil {
			return "ERROR: Invalid credentials"
		}

		s.connMutex.Lock()
		if connInfo, exists := s.connections[conn]; exists {
			connInfo.authenticated = true
			connInfo.username = username
		}
		s.connMutex.Unlock()
		return "OK: Authenticated"

	case "PUT":
		if len(parts) < 3 {
			return "ERROR: PUT requires key and value"
		}
		key := []byte(parts[1])
		value := []byte(parts[2])
		err := s.db.Put(key, value)
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err)
		}
		return "OK"

	case "GET":
		if len(parts) < 2 {
			return "ERROR: GET requires key"
		}
		key := []byte(parts[1])
		val, err := s.db.Get(key)
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err)
		}
		return string(val)

	case "DELETE":
		if len(parts) < 2 {
			return "ERROR: DELETE requires key"
		}
		key := []byte(parts[1])
		err := s.db.Delete(key)
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err)
		}
		return "OK"

	case "CLOSE":
		return "CLOSING"

	default:
		return "ERROR: Unknown command"
	}
}

// Stop stops the TCP server
func (s *TCPServer) Stop() error {
	close(s.stop)

	// Close all connections
	s.connMutex.Lock()
	for conn := range s.connections {
		conn.Close()
	}
	s.connections = make(map[*net.TCPConn]*tcpConnection)
	s.connMutex.Unlock()

	s.server.Close()
	s.wg.Wait()
	return nil
}
