package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/s3eon/s3eon/internal/s3proxy"
)

var (
	masterKey string
	host      string
	port      string

	downstreamID       string
	downstreamKey      string
	downstreamUrlStyle int

	upstreamID       string
	upstreamKey      string
	upstreamUrlStyle int
	upstreamEndpoint string
	upstreamRegion   string
	upstreamCAFile   string

	hkdfInfoTemplate string
)

func init() {
	flag.StringVar(&masterKey, "master-key", getEnvOrDefault("S3EON_MASTER_KEY", ""), "Master key for deriving per-object SSE-C keys")
	flag.StringVar(&host, "host", getEnvOrDefault("S3EON_HOST", ""), "Host to listen on")
	flag.StringVar(&port, "port", getEnvOrDefault("S3EON_PORT", "8080"), "Port to listen on")

	flag.StringVar(&downstreamID, "downstream-access-key-id", getEnvOrDefault("S3EON_DOWNSTREAM_ACCESS_KEY_ID", ""), "Downstream S3 access key ID")
	flag.StringVar(&downstreamKey, "downstream-secret-access-key", getEnvOrDefault("S3EON_DOWNSTREAM_SECRET_ACCESS_KEY", ""), "Downstream S3 secret access key")
	flag.IntVar(&downstreamUrlStyle, "downstream-url-style", toIntOrDefault(os.Getenv("S3EON_DOWNSTREAM_URL_STYLE"), 1), "Downstream S3 URL style (0=path, 1=virtual host)")

	flag.StringVar(&upstreamID, "upstream-access-key-id", getEnvOrDefault("S3EON_UPSTREAM_ACCESS_KEY_ID", ""), "Upstream S3 access key ID")
	flag.StringVar(&upstreamKey, "upstream-secret-access-key", getEnvOrDefault("S3EON_UPSTREAM_SECRET_ACCESS_KEY", ""), "Upstream S3 secret access key")
	flag.StringVar(&upstreamEndpoint, "upstream-endpoint", getEnvOrDefault("S3EON_UPSTREAM_ENDPOINT", ""), "Upstream S3 endpoint including the url scheme")
	flag.StringVar(&upstreamRegion, "upstream-region", getEnvOrDefault("S3EON_UPSTREAM_REGION", "us-east-1"), "Upstream S3 region")
	flag.StringVar(&upstreamCAFile, "upstream-ca-file", getEnvOrDefault("S3EON_UPSTREAM_CA_FILE", ""), "Additional CA certificates for upstream S3")
	flag.IntVar(&upstreamUrlStyle, "upstream-url-style", toIntOrDefault(os.Getenv("S3EON_UPSTREAM_URL_STYLE"), 1), "Upstream S3 URL style (0=path, 1=virtual host)")

	flag.StringVar(&hkdfInfoTemplate, "hkdf-info-template", getEnvOrDefault("S3EON_HKDF_INFO_TEMPLATE", ""), "Template for hkdf info to derive per-object SSE-C keys")
}

func getEnvOrDefault(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}

func toIntOrDefault(value string, defaultValue int) int {
	if v, err := strconv.Atoi(value); err == nil {
		return v
	}
	return defaultValue
}

func main() {
	flag.Parse()

	if masterKey == "" || upstreamID == "" || upstreamKey == "" || upstreamEndpoint == "" {
		flag.Usage()
		os.Exit(1)
	}

	if downstreamID == "" && downstreamKey == "" {
		downstreamID = upstreamID
		downstreamKey = upstreamKey
	}

	downstreamCreds := aws.Credentials{
		AccessKeyID:     downstreamID,
		SecretAccessKey: downstreamKey,
	}

	upstreamCreds := aws.Credentials{
		AccessKeyID:     upstreamID,
		SecretAccessKey: upstreamKey,
	}

	opts := []s3proxy.S3ProxyOptFunc{
		s3proxy.WithSSECMasterKey(masterKey),
		s3proxy.WithDownstream(s3proxy.S3URLStyle(downstreamUrlStyle)),
		s3proxy.WithUpstream(upstreamEndpoint, upstreamRegion, s3proxy.S3URLStyle(upstreamUrlStyle)),
		s3proxy.WithCredentialMap(downstreamCreds, upstreamCreds),
	}
	if upstreamCAFile != "" {
		opts = append(opts, s3proxy.WithAdditionalCACert(upstreamCAFile))
	}
	if hkdfInfoTemplate != "" {
		opts = append(opts, s3proxy.WithHKDFInfoTemplate(hkdfInfoTemplate))
	}
	s3Proxy, err := s3proxy.NewS3Proxy(opts...)
	if err != nil {
		slog.Default().Error("Failed to create S3 proxy", "error", err)
		os.Exit(1)
	}

	addr := fmt.Sprintf("%s:%s", host, port)
	slog.Default().Info("Starting S3", "addr", addr)
	if err := s3Proxy.ListenAndServe(addr); err != nil {
		slog.Default().Error("Failed to start server", "error", err)
		os.Exit(1)
	}
}
