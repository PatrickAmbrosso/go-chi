package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// JWT secret key
const jwtSecret = "your_secret_key"

// Create a new logger instance
var logger = log.NewWithOptions(os.Stderr, log.Options{
	ReportTimestamp: true,
	ReportCaller:    false,
})

// Handlers
func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	token, err := generateToken(username, password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"token":"` + token + `"}`))
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, World!"))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Healthy"))
}

func openHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello there, this route is open..."))
}

// JWT Middleware
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, http.ErrNoLocation
			}
			return []byte(jwtSecret), nil
		})

		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Token generation function
func generateToken(username, password string) (string, error) {
	if username != "admin" || password != "password" {
		return "", http.ErrNoLocation // Invalid credentials
	}

	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(), // Token expires in 1 hour
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func main() {
	// Create a new router
	r := chi.NewRouter()

	// Middleware setup
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(10 * time.Second)) // Sets a timeout for handlers

	// Custom middleware for logging with Charm's logger
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Log incoming request details
			logger.Info("Request received",
				"method", r.Method,
				"url", r.URL.String(),
				"request_id", middleware.GetReqID(r.Context()))
			next.ServeHTTP(w, r)
		})
	})

	// Define routes
	r.Post("/login", loginHandler)
	r.With(jwtMiddleware).Get("/", rootHandler)
	r.With(jwtMiddleware).Get("/health", healthHandler)
	r.Get("/open", openHandler)

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("route does not exist"))
	})

	// Create a custom server with a timeout for graceful shutdown
	srv := &http.Server{
		Addr:    "127.0.0.1:2345",
		Handler: r,
	}

	// Graceful shutdown setup
	idleConnsClosed := make(chan struct{})
	go func() {
		// Listen for interrupt signals
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint

		// Received an interrupt signal, initiate graceful shutdown
		logger.Info("Shutting down server...")

		// Create a context with a timeout to allow existing connections to complete
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			// Error from closing listeners, or context timeout:
			logger.Fatalf("Server shutdown failed: %v", err)
		}

		close(idleConnsClosed)
	}()

	logger.Infof("Starting server on port %s", srv.Addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		// If server fails to start for any reason
		logger.Fatalf("Server failed: %v", err)
	}

	<-idleConnsClosed
	logger.Info("Server exited gracefully")
}
