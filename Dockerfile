# syntax=docker/dockerfile:1.4


FROM golang:1.25 AS builder
WORKDIR /app
COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o app .


    # Final stage
FROM gcr.io/distroless/base-debian12

WORKDIR /app
COPY --from=builder /app/app .

USER nonroot:nonroot
ENTRYPOINT ["./app"]