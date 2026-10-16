FROM golang:1.27-alpine AS builder

RUN apk add --no-cache make git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN make build

FROM alpine:3.24

RUN apk add --no-cache ca-certificates

WORKDIR /root/

COPY --from=builder /app/bin/ambicert .

RUN chmod +x ./ambicert

ENTRYPOINT ["./ambicert"]
