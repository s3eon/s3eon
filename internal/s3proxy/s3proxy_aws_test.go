// SPDX-License-Identifier: AGPL-3.0-only
package s3proxy

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func newAWSProxy(t *testing.T) (rp *S3Proxy, s *httptest.Server, bucket string) {
	// define upstream data
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	bucket = "test-" + uuid.New().String()
	region := "us-east-1"
	if accessKey == "" || secretKey == "" {
		t.Skip("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set")
	}

	cfg, err := config.LoadDefaultConfig(t.Context(), config.WithRegion(region))
	require.NoError(t, err)
	client := s3.NewFromConfig(cfg)

	// setup bucket
	_, err = client.CreateBucket(t.Context(), &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})
	require.NoError(t, err)
	t.Logf("created bucket %s", bucket)

	// add cleanup
	t.Cleanup(func() {
		_, err = client.DeleteBucket(context.Background(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucket),
		})
		require.NoError(t, err)
		t.Logf("deleted bucket %s", bucket)
	})

	// create proxy
	rp, err = NewS3Proxy(
		WithSSECMasterKey("Da3ei2WFuf3tR5JXHJzSsqbpdmbYk3XkbKTFu$jcVW@ap@H5m^7Db^bq@ePMCA5x"),
		WithDownstream(UrlStylePath),
		WithUpstream("https://s3.amazonaws.com", region, UrlStyleVirtualHosted),
		WithCredentialMap(
			aws.Credentials{
				AccessKeyID:     uuid.New().String(),
				SecretAccessKey: uuid.New().String(),
			},
			aws.Credentials{
				AccessKeyID:     accessKey,
				SecretAccessKey: secretKey,
			},
		),
		WithCredentialMap(
			aws.Credentials{
				AccessKeyID:     uuid.New().String(),
				SecretAccessKey: uuid.New().String(),
			},
			aws.Credentials{
				AccessKeyID:     accessKey,
				SecretAccessKey: secretKey,
			},
		),
	)
	require.NoError(t, err)
	s = httptest.NewTLSServer(rp)

	return
}
