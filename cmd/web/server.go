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

type server struct {
	nvdService       cve.Fetcher
	osvService       cve.Fetcher
	geminiService    cve.AIAnalyzer
	webSearchService cve.WebSearcher
	logger           *logger.Logger
}

func newServer() (*server, error) {
	log := logger.New()

	nvdService, err := NewNVDService()
	if err != nil {
		return nil, fmt.Errorf("failed to create NVD service: %w", err)
	}

	osvService := NewOSVService()

	geminiService, err := NewGeminiService()
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini service: %w", err)
	}

	webSearchService := NewWebSearchService()

	return &server{
		nvdService:       nvdService,
		osvService:       osvService,
		geminiService:    geminiService,
		webSearchService: webSearchService,
		logger:           log,
	}, nil
}

func (s *server) run() error {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	mux := s.routes()
	
	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
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
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	s.logger.Info("Shutting down server")
	
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	s.logger.Info("Server shutdown complete")
	return nil
}

func (s *server) routes() http.Handler {
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