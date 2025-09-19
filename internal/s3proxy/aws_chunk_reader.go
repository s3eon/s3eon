// SPDX-License-Identifier: AGPL-3.0-only
package s3proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/minio/sha256-simd"
)

type AWSChunkedReader struct {
	trailer       http.Header
	cred          aws.Credentials
	src           io.ReadCloser
	reader        *bufio.Reader
	signer        *v4.StreamSigner
	signingTime   time.Time
	signingRegion string

	chunk          bytes.Buffer // current chunk
	chunkSignature bytes.Buffer
	left           int // bytes left in current chunk

	eof bool  // whether we've hit the final 0 chunk
	err error // sticky error
}

// NewAWSChunkedReader wraps a reader containing the AWS streaming signed payload.
func NewAWSChunkedReader(r *http.Request, cred aws.Credentials, sig string, region string, signingTime time.Time) *AWSChunkedReader {
	if r.Trailer == nil {
		r.Trailer = make(http.Header)
		for _, h := range r.Header.Values("x-amz-trailer") {
			r.Trailer.Set(h, "")
		}
	}
	r.Header.Del("x-amz-trailer")

	sigb, _ := hex.DecodeString(sig)
	signer := v4.NewStreamSigner(cred, "s3", region, sigb)
	return &AWSChunkedReader{
		cred:          cred,
		trailer:       r.Trailer,
		src:           r.Body,
		reader:        bufio.NewReader(r.Body),
		signer:        signer,
		signingRegion: region,
		signingTime:   signingTime,
	}
}

func (c *AWSChunkedReader) Read(p []byte) (int, error) {
	// check if terminal state
	if c.err != nil {
		return 0, c.err
	}
	if c.eof {
		return 0, io.EOF
	}

	// if no data left for the current chunk, parse next chunk header after validating the previous chunk
	if c.left == 0 {
		c.err = c.verifyChunkSignature()
		if c.err != nil {
			return 0, c.err
		}

		c.err = c.readHeader()
		if c.err != nil && c.err != io.EOF {
			return 0, c.err
		}
		if c.err == io.EOF {
			err := c.verifyChunkSignature()
			if err != nil {
				c.err = err
				return 0, c.err
			}
			err = c.ParseTrailer()
			if err != nil {
				c.err = err
				return 0, c.err
			}
			return 0, io.EOF
		}
	}

	// read up to min(len(p), left)
	n := min(len(p), c.left)
	n, c.err = c.reader.Read(p[:n])
	if c.err != nil {
		return n, c.err
	}
	c.chunk.Write(p[:n])
	c.left -= n

	// if we just finished a chunk, consume trailing CRLF
	if c.left == 0 {
		if _, c.err = c.reader.Discard(2); c.err != nil {
			return n, c.err
		}
	}

	return n, nil
}

func (c *AWSChunkedReader) verifyChunkSignature() error {
	if c.chunk.Len() == 0 && !c.eof {
		return nil
	}

	b, err := c.signer.GetSignature(context.Background(), nil, c.chunk.Bytes(), c.signingTime)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(b, c.chunkSignature.Bytes()) == 0 {
		return fmt.Errorf("chunk signature mismatch")
	}
	return nil
}

func (c *AWSChunkedReader) readHeader() error {
	header, err := c.reader.ReadBytes('\n')
	if err != nil {
		c.err = err
		return err
	}
	header = bytes.TrimRight(header, "\r\n")

	parts := bytes.SplitN(header, []byte(";"), 2)
	if len(parts) < 2 {
		c.err = fmt.Errorf("invalid chunk header: %q", header)
		return c.err
	}

	sizeHex := parts[0]
	size, err := strconv.ParseInt(string(sizeHex), 16, 64)
	if err != nil {
		c.err = fmt.Errorf("invalid chunk size %q: %v", sizeHex, err)
		return c.err
	}

	c.left = int(size)
	c.chunk.Reset()
	h := hex.NewDecoder(bytes.NewReader(bytes.TrimPrefix(parts[1], []byte("chunk-signature="))))
	c.chunkSignature.Reset()
	c.chunkSignature.ReadFrom(h)

	if size == 0 {
		return io.EOF
	}

	return nil
}

func (c *AWSChunkedReader) ParseTrailer() (err error) {
	if len(c.trailer) == 0 {
		return
	}

	sha256h := newSHA256Hasher()
	defer sha256h.Close()

	var sig string
	// extract trailer and sinature
	for {
		bh, err := c.reader.ReadBytes(':')
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		bv, err := c.reader.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		h := strings.TrimSuffix(string(bh), ":")
		if h == "\r\nx-amz-trailer-signature" {
			sig = string(bytes.TrimSuffix(bv, []byte("\r\n")))
			c.reader.Discard(2)
			break
		}

		sha256h.Write(bh)
		sha256h.Write(bv)

		v := strings.TrimSuffix(string(bv), "\n")
		c.trailer.Set(h, v)
	}

	// validate signature
	{
		hmac256 := func(key, data []byte) []byte {
			hash := hmac.New(sha256.New, key)
			hash.Write(data)
			return hash.Sum(nil)
		}
		date := hmac256([]byte("AWS4"+c.cred.SecretAccessKey), []byte(c.signingTime.Format("20060102")))
		location := hmac256(date, []byte(c.signingRegion))
		service := hmac256(location, []byte("s3"))
		signingKey := hmac256(service, []byte("aws4_request"))

		stringToSign := strings.Join([]string{
			"AWS4-HMAC-SHA256-TRAILER",
			c.signingTime.Format("20060102T150405Z"),
			strings.Join([]string{
				c.signingTime.Format("20060102"),
				c.signingRegion,
				"s3",
				"aws4_request",
			}, "/"),
			hex.EncodeToString(c.chunkSignature.Bytes()),
			hex.EncodeToString(sha256h.Sum(nil)),
		}, "\n")

		signature := hex.EncodeToString(hmac256(signingKey, []byte(stringToSign)))
		if subtle.ConstantTimeCompare([]byte(sig), []byte(signature)) == 0 {
			c.trailer = http.Header{}
			return fmt.Errorf("trailer signature mismatch")
		}
	}

	return
}

func (c *AWSChunkedReader) Close() error {
	return c.src.Close()
}
