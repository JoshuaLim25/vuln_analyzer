FROM golang:1.21-alpine AS build

# Install ca-certificates for HTTPS requests and tzdata for timezone support
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# grab dependency files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# source code
COPY . .

# Build the application
# NOTE: CGO_ENABLED=0 creates a static binary, GOOS=linux ensures Linux compatibility
RUN CGO_ENABLED=0 GOOS=linux go build -o cve-analyzer ./cmd/web

# Final minimal image
FROM scratch

# Copy CA certificates and timezone data for HTTPS requests
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo

# Copy binary
COPY --from=build /app/cve-analyzer /bin/cve-analyzer

# Copy static files needed by the application
COPY --from=build /app/ui /ui

# port that Cloud Run expects
EXPOSE 8080

# Run app
ENTRYPOINT ["/bin/cve-analyzer"]
