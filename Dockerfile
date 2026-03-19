# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o logwatch .

# Runtime stage — tiny image
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /build/logwatch .

# Data directory for whitelist/blacklist persistence
RUN mkdir -p /data
VOLUME /data

ENTRYPOINT ["/app/logwatch"]
