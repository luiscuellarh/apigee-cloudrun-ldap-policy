# Stage 1: Build static Go binary
FROM golang:1.22-alpine AS builder
WORKDIR /app

COPY go.mod ./
COPY *.go ./
COPY providers.json ./providers.json
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /ldap-policy-service .

# Stage 2: Hardened Distroless runtime (~12MB, ~20ms cold start)
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /ldap-policy-service /ldap-policy-service
COPY --from=builder /app/providers.json /etc/ldap/providers.json
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/ldap-policy-service"]
