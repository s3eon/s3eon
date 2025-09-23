# syntax=docker/dockerfile:1.4


FROM golang:1.25 AS builder
WORKDIR /app
COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o app .


    # Final stage
FROM scratch

WORKDIR /app
COPY --from=builder /app/app .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["./app"]
