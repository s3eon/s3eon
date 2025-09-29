package s3proxy

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type contextKey struct{}

type contextValue struct {
	context context.Context

	credential credential
	object     objectInfo
	action     string
	sourceIP   string
}

type credential struct {
	downstream aws.Credentials
	upstream   aws.Credentials
}

type objectInfo struct {
	endpoint string
	bucket   string
	key      string
}
