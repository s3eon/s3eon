package s3proxy

import (
	"context"
	"net/url"
	"text/template"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type contextKey struct{}

type Context struct {
	context context.Context

	Upstream   UpstreamInfo
	Object     ObjectInfo
	Credential Credential
	Action     string
	SourceIP   string

	hkdfInfo *template.Template
}

type Credential struct {
	Downstream aws.Credentials
	Upstream   aws.Credentials
}

type ObjectInfo struct {
	Hostname string
	Bucket   string
	Key      string
}

type UpstreamInfo struct {
	Endpoint url.URL
	Style    S3URLStyle
	Region   string
}
