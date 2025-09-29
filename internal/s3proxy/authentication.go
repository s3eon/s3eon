package s3proxy

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (s *S3Proxy) authenticate(req *http.Request) (_ *http.Request, err error) {
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

	obj, err := parseS3Url(req.URL, s.downstreamURLStyle)
	if err != nil {
		return
	}

	req = req.WithContext(context.WithValue(req.Context(), contextKey{}, contextValue{
		context:    req.Context(),
		credential: cred,
		object:     obj,
		action:     detectS3Action(req, obj.bucket, obj.key),
		sourceIP:   s.ipExtractor.ExtractClientIP(req),
	}))
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

func parseS3Url(u *url.URL, style S3URLStyle) (obj objectInfo, err error) {
	if u.Path == "" || u.Path == "/" {
		return objectInfo{
			endpoint: u.Host,
			bucket:   "",
			key:      "",
		}, nil
	}

	switch style {
	case UrlStylePath:
		parts := strings.SplitN(u.Path, "/", 3)
		if len(parts) != 3 {
			return obj, fmt.Errorf("invalid path: %q", u.Path)
		}

		obj.endpoint = u.Host
		obj.bucket = parts[1]
		obj.key = strings.Trim(parts[2], "/")

	case UrlStyleVirtualHosted:
		parts := strings.SplitN(u.Host, ".", 2)
		if len(parts) != 2 {
			return obj, fmt.Errorf("invalid host: %q", u.Host)
		}

		obj.endpoint = parts[1]
		obj.bucket = parts[0]
		obj.key = strings.Trim(u.Path, "/")
	}
	return
}
