package s3proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	transport "github.com/aws/smithy-go/endpoints"
	"github.com/minio/minio-go/v7"
	mcredentials "github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/require"
)

func TestS3Proxy(t *testing.T) {
	testdata := []struct {
		Scenario string
		Factory  func(t *testing.T) (rp *S3Proxy, s *httptest.Server, bucket string)
	}{
		{"Minio", newMinioProxy},
		{"AWS", newAWSProxy},
	}

	for _, tt := range testdata {
		t.Run(tt.Scenario, func(t *testing.T) {
			proxy, s, bucket := tt.Factory(t)
			httpClient := s.Client()

			var cred credential
			for _, v := range proxy.credentials {
				cred = v
				break
			}

			// content
			key := "hello world.txt"
			content := make([]byte, 22*1024*1024)
			_, err := rand.Read(content)
			require.NoError(t, err)

			t.Run("AWSSdk", func(t *testing.T) {
				// Build AWS config with static credentials and custom endpoint
				cfg, err := config.LoadDefaultConfig(t.Context(),
					config.WithRegion("us-east-1"),
					config.WithHTTPClient(httpClient),
					config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
						cred.downstream.AccessKeyID, cred.downstream.SecretAccessKey, ""),
					),
				)
				require.NoError(t, err)
				client := s3.NewFromConfig(cfg, func(o *s3.Options) {
					o.UsePathStyle = true
					o.EndpointResolverV2 = &tStaticResolver{url: s.URL}
				})
				clientPresign := s3.NewPresignClient(client)

				// list bucket
				_, err = client.ListBuckets(t.Context(), &s3.ListBucketsInput{})
				require.NoError(t, err)

				// first upload
				_, err = client.PutObject(t.Context(), &s3.PutObjectInput{
					Bucket:      aws.String(bucket),
					Key:         aws.String(key),
					Body:        bytes.NewReader(content),
					ContentType: aws.String("text/plain"),
				})
				require.NoError(t, err)

				// multipart upload
				createResp, err := client.CreateMultipartUpload(t.Context(), &s3.CreateMultipartUploadInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(key),
				})
				require.NoError(t, err)
				uploadID := *createResp.UploadId

				var completedParts []types.CompletedPart
				partSize := 5 * 1024 * 1024 // 5MB minimum (except last part)
				for i := 0; i*partSize < len(content); i++ {
					start := i * partSize
					end := min(start+partSize, len(content))
					partNumber := int32(i + 1)

					partResp, err := client.UploadPart(t.Context(), &s3.UploadPartInput{
						Bucket:     aws.String(bucket),
						Key:        aws.String(key),
						PartNumber: aws.Int32(partNumber),
						UploadId:   aws.String(uploadID),
						Body:       bytes.NewReader(content[start:end]),
					})
					require.NoError(t, err)

					completedParts = append(completedParts, types.CompletedPart{
						ETag:       partResp.ETag,
						PartNumber: aws.Int32(partNumber),
					})
				}

				_, err = client.CompleteMultipartUpload(t.Context(), &s3.CompleteMultipartUploadInput{
					Bucket:   aws.String(bucket),
					Key:      aws.String(key),
					UploadId: aws.String(uploadID),
					MultipartUpload: &types.CompletedMultipartUpload{
						Parts: completedParts,
					},
				})
				require.NoError(t, err)

				// copy
				_, err = client.CopyObject(t.Context(), &s3.CopyObjectInput{
					Bucket:     aws.String(bucket),
					Key:        aws.String(key + ".copy"),
					CopySource: aws.String(bucket + "/" + key),
				})
				require.NoError(t, err)

				// get
				get, err := client.GetObject(t.Context(), &s3.GetObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(key + ".copy"),
				})
				require.NoError(t, err)
				defer get.Body.Close()

				// check
				c, err := io.ReadAll(get.Body)
				require.NoError(t, err)
				require.Equal(t, content, c)

				// presigned PUT
				ps, err := clientPresign.PresignPutObject(t.Context(), &s3.PutObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(key),
					Body:   bytes.NewReader(content),
				}, s3.WithPresignExpires(15*time.Minute))
				require.NoError(t, err)
				tDoPresignRequest(t, httpClient, ps, bytes.NewReader(content))

				// presigned GET
				psg, err := clientPresign.PresignGetObject(t.Context(), &s3.GetObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(key),
				}, s3.WithPresignExpires(15*time.Minute))
				require.NoError(t, err)
				tDoPresignRequest(t, httpClient, psg, nil)

				// delete
				_, err = client.DeleteObject(t.Context(), &s3.DeleteObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(key),
				})
				require.NoError(t, err)
				_, err = client.DeleteObject(t.Context(), &s3.DeleteObjectInput{
					Bucket: aws.String(bucket),
					Key:    aws.String(key + ".copy"),
				})
				require.NoError(t, err)

			})

			t.Run("MinioSDK", func(t *testing.T) {
				// use minio client
				u, _ := url.Parse(s.URL)
				minioClient, err := minio.New(u.Host, &minio.Options{
					Creds:           mcredentials.NewStaticV4(cred.downstream.AccessKeyID, cred.downstream.SecretAccessKey, ""),
					Transport:       httpClient.Transport,
					TrailingHeaders: true,
					Secure:          u.Scheme == "https",
				})
				require.NoError(t, err)

				_, err = minioClient.PutObject(t.Context(),
					bucket, key,
					bytes.NewBuffer(content), int64(len(content)),
					minio.PutObjectOptions{
						ContentType: "application/octet-stream",
						Checksum:    minio.ChecksumCRC32C,
					})
				require.NoError(t, err)

				err = minioClient.RemoveObject(t.Context(), bucket, key, minio.RemoveObjectOptions{})
				require.NoError(t, err)
			})
		})
	}

}

type tStaticResolver struct{ url string }

func (s *tStaticResolver) ResolveEndpoint(ctx context.Context, params s3.EndpointParameters) (transport.Endpoint, error) {
	u := s.url
	if params.Bucket != nil {
		u += "/" + *params.Bucket
	}
	ur, err := url.Parse(u)
	if err != nil {
		return transport.Endpoint{}, err
	}
	return transport.Endpoint{
		URI: *ur,
	}, nil
}

func tDoPresignRequest(t *testing.T, httpClient *http.Client, ps *v4.PresignedHTTPRequest, body io.Reader) {
	req, err := http.NewRequest(ps.Method, ps.URL, body)
	require.NoError(t, err)
	for k, vals := range ps.SignedHeader {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(b))
}
