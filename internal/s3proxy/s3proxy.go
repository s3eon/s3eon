package s3proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

var _ http.Handler = &S3Proxy{}

type S3URLStyle int

const (
	UrlStylePath S3URLStyle = iota
	UrlStyleVirtualHosted
)

type site struct {
	downstreamHostname string
	downstreamURLStyle S3URLStyle

	upstreamURLStyle S3URLStyle
	upstreamEndpoint *url.URL
	upstreamRegion   string

	credentials map[string]Credential
}

type S3Proxy struct {
	masterKey string
	signer    *v4.Signer

	proxy   *cancelableProxy
	proxyCA *x509.CertPool

	sites map[string]site

	ipExtractor *ipExtractor
}

func NewS3Proxy(opts ...S3ProxyOptFunc) (s *S3Proxy, err error) {
	s = &S3Proxy{
		signer: v4.NewSigner(
			func(signer *v4.SignerOptions) {
				signer.DisableSessionToken = true
				signer.DisableHeaderHoisting = true
				signer.DisableURIPathEscaping = true
			},
		),
		sites: map[string]site{},
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	s.proxy = newCancellableProxy(httputil.ReverseProxy{
		Transport: newCancellableTransport(&http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: s.proxyCA,
			},
		}),
	}, s.rewrite)
	return
}

func (s *S3Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r, err := s.authenticate(r)
	if err != nil {
		slog.Default().Error("failed to validate auth", "error", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	s.proxy.ServeHTTP(w, r)
}

func (s *S3Proxy) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s)
}
