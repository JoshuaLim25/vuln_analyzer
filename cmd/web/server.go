package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vuln_analyzer/internal/cve"
	"vuln_analyzer/internal/logger"
)

// Server configuration constants
const (
	DefaultPort     = "5000"
	ReadTimeout     = 10 * time.Second
	WriteTimeout    = 30 * time.Second
	IdleTimeout     = 60 * time.Second
	ShutdownTimeout = 5 * time.Second
)

// Server represents the HTTP server with its dependencies.
type Server struct {
	nvdService    cve.Fetcher
	osvService    cve.Fetcher
	aiService     cve.Analyzer
	searchService cve.Searcher
	logger        *logger.Logger
}

// NewServer creates a new server instance with all required dependencies.
func NewServer() (*Server, error) {
	log := logger.New()

	nvdService, err := NewNVDService()
	if err != nil {
		return nil, fmt.Errorf("failed to create NVD service: %w", err)
	}

	osvService := NewOSVService()

	aiService, err := NewGeminiService()
	if err != nil {
		return nil, fmt.Errorf("failed to create AI service: %w", err)
	}

	searchService := NewWebSearchService()

	return &Server{
		nvdService:    nvdService,
		osvService:    osvService,
		aiService:     aiService,
		searchService: searchService,
		logger:        log,
	}, nil
}

// Run starts the HTTP server with graceful shutdown support.
func (s *Server) Run() error {
	port := os.Getenv("PORT")
	if port == "" {
		port = DefaultPort
	}

	mux := s.routes()

	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}

	// Create context for graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		s.logger.Info("Starting server",
			slog.String("port", port),
			slog.String("addr", httpServer.Addr))

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("server failed: %w", err)
		}
		serverErr <- nil
	}()

	// Wait for shutdown signal or server error
	select {
	case <-ctx.Done():
		s.logger.Info("Shutdown signal received")
	case err := <-serverErr:
		if err != nil {
			return err
		}
	}

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer shutdownCancel()

	s.logger.Info("Shutting down server")

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	s.logger.Info("Server shutdown complete")
	return nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Static files
	fileServer := http.FileServer(http.Dir("./ui/static/"))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))

	// Routes
	mux.HandleFunc("/", s.home)
	mux.HandleFunc("/api/health", s.health)
	mux.HandleFunc("/api/cve", s.handleCVE)

	// Add middleware
	handler := RequestID(mux)
	handler = Recovery(s.logger.Logger)(handler)
	handler = Security(handler)

	return handler
}
