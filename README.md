# CVE Vulnerability Analyzer

A Go web application for analyzing CVE vulnerabilities with AI-powered summaries and multi-source data aggregation.

## Features

- Multi-source CVE data: Fetches from NVD and OSV databases
- AI-powered summaries
- Web search integration: Gathers additional context from GitHub and search engines
- Modern UI: Clean, responsive interface with real-time updates
- Structured logging, middleware, graceful shutdown

## Quick Start

```bash
# TODO: Set required environment variables
# export NVD_API_KEY="your_nvd_api_key"
# export GEMINI_API_KEY="your_gemini_api_key"

# Run the application
go run ./cmd/web
```

Server runs on port 8080 by default. Set `PORT` environment variable to change.

## Environment Variables

- `NVD_API_KEY` - Required: NVD API key for CVE data
- `GEMINI_API_KEY` - Required: Google Gemini API key for AI summaries
- `PORT` - Optional: Server port (default: 8080)
- `LOG_LEVEL` - Optional: debug, info, warn, error (default: info)
- `LOG_FORMAT` - Optional: json, text (default: json)

## API Endpoints

- `GET /` - Web interface
- `POST /api/cve` - CVE analysis endpoint
- `GET /api/health` - Health check

## Architecture

- Interface-based design with dependency injection
- Graceful error handling and fallback strategies
- Structured logging with contextual information
- Security middleware
