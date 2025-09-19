// SPDX-License-Identifier: AGPL-3.0-only

package s3proxy

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7/pkg/signer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSChunkedReader(t *testing.T) {
	// Input payload
	origData := make([]byte, 12*1024*1024)
	_, err := rand.Read(origData)
	require.NoError(t, err)
	trailer := uuid.NewString()

	// Test credentials
	region := "us-east-1"
	accessKey := "AKIDEXAMPLE"
	secretKey := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

	// Validating Server
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _, sig, _, err := parseAuthorizationHeader(req.Header.Get("Authorization"))
		require.NoError(t, err)
		ti, err := parseAmzDateOrDate(req.Header)
		require.NoError(t, err)
		r := NewAWSChunkedReader(req, aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}, sig, region, ti)
		defer r.Close()

		w.Header().Set("trailer", "x-trailer, x-test")
		_, err = io.Copy(w, r)
		require.NoError(t, err)
		w.Header().Set("x-trailer", req.Trailer.Get("x-trailer"))
		w.Header().Set("x-test", req.Trailer.Get("x-test"))
	}))

	req, err := http.NewRequest("PUT", s.URL+"/bucket/object", bytes.NewReader(origData))
	require.NoError(t, err)
	req.Trailer = http.Header{"x-trailer": {trailer}, "x-test": {t.Name()}}
	signer.StreamingSignV4(
		req, accessKey, secretKey, "", region, int64(len(origData)), time.Now(), newSHA256Hasher(),
	)

	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()

	// Verify response
	data, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, len(origData), len(data))
	assert.Equal(t, origData, data)

	// Verify trailers
	assert.Len(t, res.Trailer, 2)
	assert.Equal(t, trailer, res.Trailer.Get("x-trailer"))
	assert.Equal(t, t.Name(), res.Trailer.Get("x-test"))
}
