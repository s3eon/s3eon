package s3proxy

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type S3ProxyOptFunc func(*S3Proxy) error

func WithSSECMasterKey(masterKey string) S3ProxyOptFunc {
	return func(s *S3Proxy) error {
		s.masterKey = masterKey
		return nil
	}
}

func WithAdditionalCACert(caCert string) S3ProxyOptFunc {
	return func(s *S3Proxy) (err error) {
		b, err := os.ReadFile(caCert)
		if err != nil {
			return fmt.Errorf("failed to read CA cert: %w", err)
		}
		s.proxyCA, err = x509.SystemCertPool()
		if err != nil {
			s.proxyCA = x509.NewCertPool()
		}
		s.proxyCA.AppendCertsFromPEM(b)
		return nil
	}
}

func WithDownstream(urlStyle S3URLStyle) S3ProxyOptFunc {
	return func(s *S3Proxy) error {
		si, ok := s.sites["*"]
		if !ok {
			si = site{}
		}

		si.downstreamURLStyle = urlStyle
		s.sites["*"] = si
		return nil
	}
}

func WithUpstream(endpoint, region string, urlStyle S3URLStyle) S3ProxyOptFunc {
	return func(s *S3Proxy) (err error) {
		si, ok := s.sites["*"]
		if !ok {
			si = site{}
		}

		si.upstreamEndpoint, err = url.Parse(endpoint)
		if err != nil {
			return
		}

		si.upstreamURLStyle = urlStyle
		si.upstreamRegion = region
		s.sites["*"] = si
		return nil
	}
}

func WithCredentialMap(downstream aws.Credentials, upstream aws.Credentials) S3ProxyOptFunc {
	return func(s *S3Proxy) error {
		si, ok := s.sites["*"]
		if !ok {
			si = site{}
		}
		if si.credentials == nil {
			si.credentials = map[string]Credential{}
		}

		si.credentials[downstream.AccessKeyID] = Credential{downstream, upstream}
		s.sites["*"] = si
		return nil
	}
}
