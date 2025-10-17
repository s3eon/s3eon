// SPDX-License-Identifier: AGPL-3.0-only
package s3proxy

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/minio/minio-go/v7/pkg/signer"
	"github.com/minio/sha256-simd"
	"golang.org/x/crypto/hkdf"
)

func (s *S3Proxy) rewrite(pr *httputil.ProxyRequest) (err error) {
	ctx, ok := pr.In.Context().Value(contextKey{}).(Context)
	if !ok {
		return cancelError{code: http.StatusUnauthorized, message: "unauthorized"}
	}

	bucket, key := ctx.Object.Bucket, ctx.Object.Key

	// non-object request
	if bucket == "" || key == "" {
		pr.SetURL(&ctx.Upstream.Endpoint)
		err = s.sign(pr, ctx)
		if err != nil {
			return cancelError{message: "failed to compute signature", err: err}
		}
		return
	}

	s.setUpstreamURL(pr, ctx)

	// no sse-c
	if s.masterKey == "" {
		err = s.sign(pr, ctx)
		if err != nil {
			return cancelError{message: "failed to compute signature", err: err}
		}
		return
	}

	err = s.attachKey(pr.Out, ctx, "X-Amz-")
	if err != nil {
		return cancelError{message: "failed to attach sse-c key", err: err}
	}

	if source := pr.In.Header.Get("X-Amz-Copy-Source"); source != "" {
		bucket, key, err := parseS3CopySource(source)
		if err != nil {
			return cancelError{code: http.StatusBadRequest, message: "invalid X-Amz-Copy-Source", err: err}
		}

		ctx := ctx
		ctx.Object.Bucket, ctx.Object.Key = bucket, key
		err = s.attachKey(pr.Out, ctx, "X-Amz-Copy-Source-")
		if err != nil {
			return cancelError{message: "failed to attach sse-c key for copy source", err: err}
		}
	}

	err = s.sign(pr, ctx)
	if err != nil {
		return cancelError{message: "failed to compute signature", err: err}
	}

	return nil
}

func (s *S3Proxy) sign(pr *httputil.ProxyRequest, ctx Context) error {
	q := pr.In.URL.Query()
	if sig := q.Get("X-Amz-Signature"); sig != "" {
		q.Del("X-Amz-Signature")
		pr.Out.URL.RawQuery = q.Encode()
		exp, _ := strconv.ParseInt(q.Get("X-Amz-Expires"), 10, 64)
		req := signer.PreSignV4(*pr.Out,
			ctx.Credential.Upstream.AccessKeyID, ctx.Credential.Upstream.SecretAccessKey,
			ctx.Credential.Upstream.SessionToken, ctx.Upstream.Region, exp)
		pr.Out.URL = req.URL
		return nil
	}

	if c := pr.In.Header.Get("x-amz-content-sha256"); strings.HasPrefix(c, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") {
		t, _ := parseAmzDateOrDate(pr.In.Header)
		pr.Out.Trailer = pr.In.Trailer
		signer.StreamingSignV4(pr.Out,
			ctx.Credential.Upstream.AccessKeyID, ctx.Credential.Upstream.SecretAccessKey,
			ctx.Credential.Upstream.SessionToken, ctx.Upstream.Region, pr.In.ContentLength, t, newSHA256Hasher())
		return nil
	}

	req := signer.SignV4(*pr.Out,
		ctx.Credential.Upstream.AccessKeyID, ctx.Credential.Upstream.SecretAccessKey,
		ctx.Credential.Upstream.SessionToken, ctx.Upstream.Region)
	pr.Out.Header.Set("Authorization", req.Header.Get("Authorization"))
	return nil
}

func (s *S3Proxy) setUpstreamURL(pr *httputil.ProxyRequest, ctx Context) {
	scheme, host, path := ctx.Upstream.Endpoint.Scheme, ctx.Upstream.Endpoint.Host, ""
	switch ctx.Upstream.Style {
	case UrlStylePath:
		path = "/" + ctx.Object.Bucket + "/" + ctx.Object.Key
	case UrlStyleVirtualHosted:
		host = ctx.Object.Bucket + "." + host
		path = "/" + ctx.Object.Key
	}

	pr.Out.URL.Scheme = scheme
	pr.Out.URL.Host = host
	pr.Out.URL.Path = path
	pr.Out.URL.RawPath = ""
	pr.Out.Host = ""
}

func (s *S3Proxy) attachKey(r *http.Request, ctx Context, headerPrefix string) error {

	keyB64, keyMD5, err := s.createSSECKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to create sse-c key: %w", err)
	}

	r.Header.Set(headerPrefix+"Server-Side-Encryption-Customer-Algorithm", "AES256")
	r.Header.Set(headerPrefix+"Server-Side-Encryption-Customer-Key", keyB64)
	r.Header.Set(headerPrefix+"Server-Side-Encryption-Customer-Key-MD5", keyMD5)
	return nil
}

func (s *S3Proxy) createSSECKey(ctx Context) (keyB64 string, keyMD5 string, err error) {
	var info []byte
	switch ctx.hkdfInfo {
	default:
		var sb bytes.Buffer
		if err := ctx.hkdfInfo.Execute(&sb, ctx); err != nil {
			return "", "", fmt.Errorf("failed to render hkdf info: %w", err)
		}
		info = sb.Bytes()
	case nil:
		endpoint := ctx.Upstream.Endpoint.Scheme + "://" + ctx.Upstream.Endpoint.Host
		info = []byte(endpoint + "/" + ctx.Object.Bucket + "/" + ctx.Object.Key)
	}
	h := hkdf.New(sha256.New, []byte(s.masterKey), nil, info)
	k := make([]byte, 32)
	if _, err := io.ReadFull(h, k); err != nil {
		return "", "", fmt.Errorf("failed to generate sse-c key: %w", err)
	}

	keyB64 = base64.StdEncoding.EncodeToString(k)
	md5Sum := md5.Sum(k)
	keyMD5 = base64.StdEncoding.EncodeToString(md5Sum[:])
	return
}

var sha256Pool = sync.Pool{New: func() any { return sha256.New() }}

type sha256Hasher struct {
	hash.Hash
}

func newSHA256Hasher() *sha256Hasher {
	return &sha256Hasher{Hash: sha256Pool.Get().(hash.Hash)}
}

func (s *sha256Hasher) Close() {
	if s.Hash == nil {
		return
	}

	s.Reset()
	sha256Pool.Put(s.Hash)
	s.Hash = nil
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
