// SPDX-License-Identifier: AGPL-3.0-only
package s3proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
)

type cancelableProxy struct {
	httputil.ReverseProxy
}

func newCancellableProxy(proxy httputil.ReverseProxy, rewrite func(*httputil.ProxyRequest) error) *cancelableProxy {
	if rewrite == nil {
		return &cancelableProxy{ReverseProxy: proxy}
	}

	proxy.Transport = newCancellableTransport(proxy.Transport)
	proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		err := rewrite(pr)
		if err != nil {
			var errc cancelError
			if !errors.As(err, &errc) {
				errc = cancelError{message: "failed to rewrite request", err: err}
			}

			cancelProxy(pr.Out, errc.Response(pr.In))
			return
		}
	}

	return &cancelableProxy{ReverseProxy: proxy}
}

type cancelableTransportKey struct{}

func cancelProxy(req *http.Request, res *http.Response) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), cancelableTransportKey{}, res))
}

type cancellableTransport struct {
	transport http.RoundTripper
}

func newCancellableTransport(t http.RoundTripper) cancellableTransport {
	if t == nil {
		t = http.DefaultTransport
	}
	return cancellableTransport{
		transport: t,
	}
}

func (c cancellableTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	res, ok := req.Context().Value(cancelableTransportKey{}).(*http.Response)
	if ok {
		return res, nil
	}

	return c.transport.RoundTrip(req)
}

type cancelError struct {
	code        int
	message     string
	contentType string
	err         error
}

func (e cancelError) Error() string {
	return fmt.Sprintf("%s: %s", e.message, e.err)
}

func (e cancelError) Unwrap() error {
	return e.err
}

func (e cancelError) Response(req *http.Request) *http.Response {
	code := e.code
	if code == 0 {
		code = http.StatusInternalServerError
	}
	ctype := e.contentType
	if ctype == "" {
		ctype = "text/plain"
	}
	return &http.Response{
		StatusCode: code,
		Proto:      req.Proto,
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{"Content-Type": []string{ctype}},
		Body:       io.NopCloser(strings.NewReader(e.message)),
		Request:    req,
	}
}
