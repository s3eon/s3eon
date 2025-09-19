// SPDX-License-Identifier: AGPL-3.0-only
package s3proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

func newMinioProxy(t *testing.T) (rp *S3Proxy, s *httptest.Server, bucket string) {
	// define upstream data
	accessKey := uuid.New().String()
	secretKey := uuid.New().String()
	bucket = "test-" + uuid.New().String()

	// run minio
	container, minioEndpoint, certFile, err := runMinioContainer(t, accessKey, secretKey, bucket)
	require.NoError(t, err)
	t.Cleanup(func() { container.Terminate(t.Context()) })

	// create proxy
	rp, err = NewS3Proxy(
		WithSSECMasterKey("Da3ei2WFuf3tR5JXHJzSsqbpdmbYk3XkbKTFu$jcVW@ap@H5m^7Db^bq@ePMCA5x"),
		WithAdditionalCACert(certFile),
		WithDownstream(UrlStylePath),
		WithUpstream(minioEndpoint, "us-east-1", UrlStylePath),
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
	s = httptest.NewServer(rp)

	return
}

func runMinioContainer(t *testing.T, accessKeyId, secretAccessKey, bucket string) (container testcontainers.Container, url, certfile string, err error) {
	certDir := t.TempDir()

	_, certfile, err = generateSelfSignedCert(certDir, []string{"localhost"})
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate self-signed cert: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:        "minio/minio:latest",
		ExposedPorts: []string{"9000/tcp", "9001/tcp"},
		Env: map[string]string{
			"MINIO_ROOT_USER":     accessKeyId,
			"MINIO_ROOT_PASSWORD": secretAccessKey,
		},
		Cmd: []string{"server", "/data", "--console-address", ":9001"},
		Mounts: []testcontainers.ContainerMount{
			{
				Source: testcontainers.GenericBindMountSource{
					HostPath: certDir,
				},
				Target:   "/root/.minio/certs",
				ReadOnly: true,
			},
		},
		WaitingFor: wait.ForExposedPort(),
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{
				tContainerLogger{t: t},
			},
		},
	}

	container, err = testcontainers.GenericContainer(t.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return
	}

	exitCode, out, err := container.Exec(t.Context(), []string{
		"sh", "-c", fmt.Sprintf(`
				mc alias set local https://localhost:9000 '%s' '%s';
				mc mb "local/%s";
			`, accessKeyId, secretAccessKey, bucket),
	}, exec.WithEnv([]string{"MC_INSECURE=true"}))
	if err != nil || exitCode != 0 {
		b, _ := io.ReadAll(out)
		err = fmt.Errorf("failed to create bucket: %s: %w", b, err)
		return
	}

	host, err := container.Host(t.Context())
	if err != nil {
		return
	}

	mappedPort, err := container.MappedPort(t.Context(), "9000")
	if err != nil {
		return
	}
	url = fmt.Sprintf("https://%s:%s", host, mappedPort.Port())

	return
}

func generateSelfSignedCert(certDir string, hosts []string) (certBytes []byte, certFile string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, "", err
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"TestOrg"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, "", err
	}

	certOut, err := os.Create(filepath.Join(certDir, "public.crt"))
	if err != nil {
		return nil, "", err
	}
	defer certOut.Close()
	certBuf := bytes.Buffer{}
	if err := pem.Encode(io.MultiWriter(certOut, &certBuf), &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, "", err
	}

	keyOut, err := os.Create(filepath.Join(certDir, "private.key"))
	if err != nil {
		return nil, "", err
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		return nil, "", err
	}

	return certBuf.Bytes(), certOut.Name(), nil
}

type tContainerLogger struct {
	t *testing.T
}

func (t tContainerLogger) Accept(l testcontainers.Log) {
	t.t.Helper()
	t.t.Log(string(l.Content))
}
