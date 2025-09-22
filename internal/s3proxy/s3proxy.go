// SPDX-License-Identifier: AGPL-3.0-only
package s3proxy

import (
	"context"
	"crypto/md5"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/minio/minio-go/v7/pkg/signer"
	"github.com/minio/sha256-simd"
	"golang.org/x/crypto/hkdf"
)

var _ http.Handler = &S3Proxy{}

type S3URLStyle int

const (
	UrlStylePath S3URLStyle = iota
	UrlStyleVirtualHosted
)

type credential struct {
	downstream aws.Credentials
	upstream   aws.Credentials
}

type credentialKey struct{}

type S3Proxy struct {
	masterKey string
	signer    *v4.Signer

	downstreamURLStyle S3URLStyle

	proxy   *cancelableProxy
	proxyCA *x509.CertPool

	upstreamURLStyle S3URLStyle
	upstreamEndpoint *url.URL
	upstreamRegion   string

	credentials map[string]credential
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
		credentials: map[string]credential{},
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

func (s *S3Proxy) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s)
}

func (s *S3Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r, err := s.validateAuth(r)
	if err != nil {
		slog.Default().Error("failed to validate auth", "error", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	s.proxy.ServeHTTP(w, r)
}

func (s *S3Proxy) validateAuth(req *http.Request) (_ *http.Request, err error) {
	hAuthz := req.Header.Get("Authorization")
	isHauthz := strings.HasPrefix(hAuthz, "AWS4-HMAC-SHA256 ")

	qAuthz := req.URL.Query().Get("X-Amz-Signature")
	isQAuthz := qAuthz != ""

	var cred credential
	switch {
	default:
		return nil, fmt.Errorf("no X-Amz-Signature or Authorization header present")
	case isHauthz && isQAuthz:
		return nil, fmt.Errorf("both X-Amz-Signature and Authorization header present")

	case isHauthz:
		cred, err = s.validateAuthHeader(req, hAuthz)
	case isQAuthz:
		cred, err = s.validateAuthQuery(req, qAuthz)
	}
	if err != nil {
		return
	}

	req = req.WithContext(context.WithValue(req.Context(), credentialKey{}, cred))
	return req, err
}

func (s *S3Proxy) validateAuthHeader(req *http.Request, authz string) (cred credential, err error) {
	keyID, region, sig1, sigh, err := parseAuthorizationHeader(authz)
	if err != nil {
		return
	}

	cred, ok := s.credentials[keyID]
	if !ok {
		return cred, fmt.Errorf("AccessKeyId mismatch")
	}

	sigt, err := parseAmzDateOrDate(req.Header)
	if err != nil {
		return cred, fmt.Errorf("failed to parse date header: %w", err)
	}

	bodyHash := req.Header.Get("x-amz-content-sha256")

	reqc := duplicateReq(req, sigh)
	err = s.signer.SignHTTP(req.Context(), cred.downstream, reqc, bodyHash, "s3", region, sigt)
	if err != nil {
		return cred, fmt.Errorf("failed to compute signature: %w", err)
	}

	sig2, err := parseSignatureFromHeader(req.Header.Get("Authorization"))
	if err != nil {
		return cred, err
	}
	if subtle.ConstantTimeCompare([]byte(sig1), []byte(sig2)) == 0 {
		return cred, fmt.Errorf("signature mismatch")
	}

	if strings.HasPrefix(bodyHash, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") {
		req.Body = NewAWSChunkedReader(req, cred.downstream, sig1, region, sigt)
		req.ContentLength, _ = strconv.ParseInt(req.Header.Get("x-amz-decoded-content-length"), 10, 64)
		req.Header.Del("content-length")
	}
	return cred, nil
}

func parseAuthorizationHeader(authz string) (accessKeyID, region, signature string, sigHeaders []string, err error) {
	authz = strings.TrimPrefix(authz, "AWS4-HMAC-SHA256 ")
	if authz == "" {
		err = fmt.Errorf("empty Authorization header")
		return
	}

	// Split into parts: Credential=..., SignedHeaders=..., Signature=...
	var credential string
	for part := range strings.SplitSeq(authz, ",") {
		part = strings.TrimSpace(part)
		if after, ok := strings.CutPrefix(part, "Credential="); ok {
			credential = after
			continue
		}

		if after, ok := strings.CutPrefix(part, "SignedHeaders="); ok {
			sigHeaders = strings.Split(after, ";")
			continue
		}

		if after, ok := strings.CutPrefix(part, "Signature="); ok {
			signature = after
			continue
		}
	}

	accessKeyID, region, err = parseAWSCredential(credential)
	return
}

func parseAWSCredential(credential string) (accessKeyID, region string, err error) {
	// Credential format: <accessKeyId>/<date>/<region>/<service>/aws4_request
	credParts := strings.Split(credential, "/")
	if len(credParts) < 5 {
		err = fmt.Errorf("malformed Credential: %s", credential)
		return
	}

	accessKeyID = credParts[0]
	region = credParts[2]
	return accessKeyID, region, nil
}

func parseSignatureFromHeader(v string) (s string, err error) {
	for part := range strings.SplitSeq(v, ",") {
		part = strings.TrimSpace(part)
		if after, ok := strings.CutPrefix(part, "Signature="); ok {
			s = after
			return
		}
	}

	return "", fmt.Errorf("no Signature found in Authorization header")
}

func duplicateReq(req *http.Request, signedHeaders []string) *http.Request {
	reqc := *req
	reqc.Header = http.Header{}
	reqc.ContentLength = -1
	for _, h := range signedHeaders {
		reqc.Header.Set(h, req.Header.Get(h))
		if strings.EqualFold(h, "content-length") {
			reqc.ContentLength = req.ContentLength
		}
	}
	return &reqc
}

func (s *S3Proxy) validateAuthQuery(req *http.Request, authz string) (cred credential, err error) {
	keyID, region, err := parseAWSCredential(req.URL.Query().Get("X-Amz-Credential"))
	if err != nil {
		return
	}

	cred, ok := s.credentials[keyID]
	if !ok {
		return cred, fmt.Errorf("AccessKeyId mismatch")
	}

	t, err := parseAmzDate(req.URL.Query().Get("X-Amz-Date"))
	if err != nil {
		return cred, fmt.Errorf("failed to parse date header: %w", err)
	}

	bodyHash := req.Header.Get("X-Amz-Content-Sha256")
	reqc := duplicateReq(req, strings.Split(req.URL.Query().Get("X-Amz-SignedHeaders"), ";"))

	sigu, _, err := s.signer.PresignHTTP(context.Background(), cred.downstream, reqc, bodyHash, "s3", region, t)
	if err != nil {
		return cred, fmt.Errorf("failed to compute signature: %w", err)
	}

	u, err := url.Parse(sigu)
	if err != nil {
		return cred, fmt.Errorf("failed to parse signature: %w", err)
	}
	authz2 := u.Query().Get("X-Amz-Signature")

	if subtle.ConstantTimeCompare([]byte(authz), []byte(authz2)) == 0 {
		return cred, fmt.Errorf("signature mismatch")
	}
	return
}

func parseAmzDateOrDate(h http.Header) (time.Time, error) {
	if amzDate := h.Get("X-Amz-Date"); amzDate != "" {
		return parseAmzDate(amzDate)
	}

	if date := h.Get("Date"); date != "" {
		t, err := time.Parse(time.RFC1123, date)
		if err == nil {
			return t, nil
		}
		t, err = time.Parse(time.RFC1123Z, date)
		if err == nil {
			return t, nil
		}
		return time.Time{}, fmt.Errorf("invalid Date format: %w", err)
	}

	return time.Time{}, fmt.Errorf("no X-Amz-Date or Date header present")
}

func parseAmzDate(amzDate string) (time.Time, error) {
	t, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid X-Amz-Date format: %w", err)
	}
	return t, nil
}

func (s *S3Proxy) rewrite(pr *httputil.ProxyRequest) (err error) {
	// non-object request
	if pr.In.URL.Path == "" || pr.In.URL.Path == "/" {
		pr.SetURL(s.upstreamEndpoint)
		err = s.sign(pr)
		if err != nil {
			return cancelError{message: "failed to compute signature", err: err}
		}
		return
	}

	_, bucket, key, err := parseS3Url(pr.In.URL, s.downstreamURLStyle)
	if err != nil {
		return cancelError{message: "invalid url", err: err}
	}

	s.setUpstreamURL(pr, bucket, key)

	// no sse-c
	if s.masterKey == "" {
		err = s.sign(pr)
		if err != nil {
			return cancelError{message: "failed to compute signature", err: err}
		}
		return
	}

	err = s.attachKey(pr.Out, "X-Amz-", bucket, key)
	if err != nil {
		return cancelError{message: "failed to attach sse-c key", err: err}
	}

	if source := pr.In.Header.Get("X-Amz-Copy-Source"); source != "" {
		bucket, key, err := parseS3CopySource(source)
		if err != nil {
			return cancelError{code: http.StatusBadRequest, message: "invalid X-Amz-Copy-Source", err: err}
		}

		err = s.attachKey(pr.Out, "X-Amz-Copy-Source-", bucket, key)
		if err != nil {
			return cancelError{message: "failed to attach sse-c key for copy source", err: err}
		}
	}

	err = s.sign(pr)
	if err != nil {
		return cancelError{message: "failed to compute signature", err: err}
	}

	return nil
}

func (s *S3Proxy) sign(pr *httputil.ProxyRequest) error {
	cred, ok := pr.In.Context().Value(credentialKey{}).(credential)
	if !ok {
		return cancelError{code: http.StatusUnauthorized, message: "unauthorized"}
	}

	q := pr.In.URL.Query()
	if sig := q.Get("X-Amz-Signature"); sig != "" {
		q.Del("X-Amz-Signature")
		pr.Out.URL.RawQuery = q.Encode()
		exp, _ := strconv.ParseInt(q.Get("X-Amz-Expires"), 10, 64)
		req := signer.PreSignV4(*pr.Out, cred.upstream.AccessKeyID, cred.upstream.SecretAccessKey, cred.upstream.SessionToken, s.upstreamRegion, exp)
		pr.Out.URL = req.URL
		return nil
	}

	if c := pr.In.Header.Get("x-amz-content-sha256"); strings.HasPrefix(c, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") {
		t, _ := parseAmzDateOrDate(pr.In.Header)
		pr.Out.Trailer = pr.In.Trailer
		signer.StreamingSignV4(pr.Out,
			cred.upstream.AccessKeyID, cred.upstream.SecretAccessKey, cred.upstream.SessionToken,
			s.upstreamRegion, pr.In.ContentLength, t, newSHA256Hasher())
		return nil
	}

	req := signer.SignV4(*pr.Out, cred.upstream.AccessKeyID, cred.upstream.SecretAccessKey, cred.upstream.SessionToken, s.upstreamRegion)
	pr.Out.Header.Set("Authorization", req.Header.Get("Authorization"))
	return nil
}

func parseS3Url(u *url.URL, style S3URLStyle) (endpoint string, bucket string, key string, err error) {
	switch style {
	case UrlStylePath:
		parts := strings.SplitN(u.Path, "/", 3)
		if len(parts) != 3 {
			return "", "", "", fmt.Errorf("invalid path: %q", u.Path)
		}

		endpoint = u.Host
		bucket = parts[1]
		key = strings.Trim(parts[2], "/")

	case UrlStyleVirtualHosted:
		parts := strings.SplitN(u.Host, ".", 2)
		if len(parts) != 2 {
			return "", "", "", fmt.Errorf("invalid host: %q", u.Host)
		}

		endpoint = parts[1]
		bucket = parts[0]
		key = strings.Trim(u.Path, "/")
	}
	return
}

func (s *S3Proxy) setUpstreamURL(pr *httputil.ProxyRequest, bucket string, key string) {
	scheme, host, path := s.upstreamEndpoint.Scheme, s.upstreamEndpoint.Host, ""
	switch s.upstreamURLStyle {
	case UrlStylePath:
		path = "/" + bucket + "/" + key
	case UrlStyleVirtualHosted:
		host = bucket + "." + host
		path = "/" + key
	}

	pr.Out.URL.Scheme = scheme
	pr.Out.URL.Host = host
	pr.Out.URL.Path = path
	pr.Out.URL.RawPath = ""
	pr.Out.Host = ""
}

func (s *S3Proxy) attachKey(r *http.Request, headerPrefix, bucket, key string) error {
	endpoint := s.upstreamEndpoint.Scheme + "://" + s.upstreamEndpoint.Host
	keyB64, keyMD5, err := s.createSSECKey(endpoint, bucket, key)
	if err != nil {
		return fmt.Errorf("failed to create sse-c key: %w", err)
	}

	r.Header.Set(headerPrefix+"Server-Side-Encryption-Customer-Algorithm", "AES256")
	r.Header.Set(headerPrefix+"Server-Side-Encryption-Customer-Key", keyB64)
	r.Header.Set(headerPrefix+"Server-Side-Encryption-Customer-Key-MD5", keyMD5)
	return nil
}

var sha256Pool = sync.Pool{New: func() any { return sha256.New() }}

type sha256Hasher struct {
	hash.Hash
}

func newSHA256Hasher() *sha256Hasher {
	return &sha256Hasher{Hash: sha256Pool.Get().(hash.Hash)}
}

func (s *sha256Hasher) Close() {
	if s.Hash != nil {
		s.Reset()
		sha256Pool.Put(s.Hash)
		s.Hash = nil
	}
}

func (s *S3Proxy) createSSECKey(endpoint, bucket, key string) (keyB64 string, keyMD5 string, err error) {
	h := hkdf.New(sha256.New, []byte(s.masterKey), nil, []byte(endpoint+"/"+bucket+"/"+key))
	k := make([]byte, 32)
	if _, err := io.ReadFull(h, k); err != nil {
		return "", "", fmt.Errorf("failed to generate sse-c key: %w", err)
	}

	keyB64 = base64.StdEncoding.EncodeToString(k)
	md5Sum := md5.Sum(k)
	keyMD5 = base64.StdEncoding.EncodeToString(md5Sum[:])
	return
}

func parseS3CopySource(copySource string) (bucket string, key string, err error) {
	// URL-decode
	decoded, err := url.PathUnescape(copySource)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode X-Amz-Copy-Source: %w", err)
	}

	// Strip any query string (e.g. ?versionId=...)
	if i := strings.IndexRune(decoded, '?'); i != -1 {
		decoded = decoded[:i]
	}

	// Access point ARN case
	if strings.HasPrefix(decoded, "arn:aws:s3:") {
		parts := strings.SplitN(decoded, "/object/", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid access point ARN format: %q", copySource)
		}
		return parts[0], parts[1], nil
	}

	// Normal bucket/key case
	trimmed := strings.TrimPrefix(decoded, "/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid bucket/key format: %q", copySource)
	}

	return parts[0], parts[1], nil
}
