package s3proxy

import (
	"context"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type contextKey struct{}

type contextValue struct {
	context context.Context

	upstream   upstreamInfo
	object     objectInfo
	credential credential
	action     string
	sourceIP   string
}

type credential struct {
	downstream aws.Credentials
	upstream   aws.Credentials
}

type objectInfo struct {
	hostname string
	bucket   string
	key      string
}

type upstreamInfo struct {
	endpoint url.URL
	style    S3URLStyle
	region   string
}
