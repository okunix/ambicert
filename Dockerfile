FROM golang:1.27-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=$(git describe --tags --always || echo 'dev')" \
    -o ambicert main.go

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /root/

COPY --from=builder /app/ambicert .

RUN chmod +x ./ambicert

ENTRYPOINT ["./ambicert"]
