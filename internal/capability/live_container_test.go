package capability

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fixtureOCI struct {
	manifest []byte
	config   []byte
	layer    []byte
	digest   string
	blobs    map[string][]byte
}

func fixtureRegistry(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"registry.cybot.invalid"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	return server
}

func fixtureDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fixtureTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	archive := tar.NewWriter(&out)
	for name, data := range files {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func fixtureOCIImage(t *testing.T, version string) fixtureOCI {
	t.Helper()
	lock := fmt.Sprintf(`{"name":"fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0","dependencies":{"lodash":%q}},"node_modules/lodash":{"name":"lodash","version":%q}}}`, version, version)
	layer := fixtureTar(t, map[string][]byte{"app/package-lock.json": []byte(lock)})
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(layer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	encode := func(value any) []byte {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	config := encode(map[string]any{"architecture": runtime.GOARCH, "os": "linux", "config": map[string]any{"WorkingDir": "/app"}, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{fixtureDigest(layer)}}})
	descriptor := func(media string, data []byte) map[string]any {
		return map[string]any{"mediaType": media, "digest": fixtureDigest(data), "size": len(data)}
	}
	manifest := encode(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": descriptor("application/vnd.oci.image.config.v1+json", config), "layers": []any{descriptor("application/vnd.oci.image.layer.v1.tar+gzip", compressed.Bytes())}})
	return fixtureOCI{manifest: manifest, config: config, layer: layer, digest: fixtureDigest(manifest), blobs: map[string][]byte{fixtureDigest(config): config, fixtureDigest(compressed.Bytes()): compressed.Bytes()}}
}

func (image fixtureOCI) layout(t *testing.T, path string) {
	t.Helper()
	descriptor := map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": image.digest, "size": len(image.manifest), "platform": map[string]string{"architecture": runtime.GOARCH, "os": "linux"}, "annotations": map[string]string{"org.opencontainers.image.ref.name": "fixture:local"}}
	index, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{descriptor}})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": index, "blobs/sha256/" + strings.TrimPrefix(image.digest, "sha256:"): image.manifest}
	for digest, data := range image.blobs {
		files["blobs/sha256/"+strings.TrimPrefix(digest, "sha256:")] = data
	}
	for name, data := range files {
		target := filepath.Join(path, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func (image fixtureOCI) archive(t *testing.T, path string) {
	t.Helper()
	config := strings.TrimPrefix(fixtureDigest(image.config), "sha256:") + ".json"
	manifest, err := json.Marshal([]map[string]any{{"Config": config, "RepoTags": []string{"fixture:local"}, "Layers": []string{"layer.tar"}}})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"manifest.json": manifest, config: image.config, "layer.tar": image.layer}
	if err := os.WriteFile(path, fixtureTar(t, files), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLiveSupplyChainContainers(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_SUPPLYCHAIN") != "1" {
		t.Skip("requires isolated container scanners and pinned datasets")
	}
	d := liveDeps(t)
	images := map[string]fixtureOCI{"positive": fixtureOCIImage(t, "4.17.20"), "negative": fixtureOCIImage(t, "9999.0.0")}
	server := fixtureRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{}"))
			return
		}
		for tag, image := range images {
			if r.URL.Path == "/v2/fixture/manifests/"+tag || r.URL.Path == "/v2/fixture/manifests/"+image.digest {
				w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
				w.Header().Set("Docker-Content-Digest", image.digest)
				_, _ = w.Write(image.manifest)
				return
			}
			for digest, data := range image.blobs {
				if r.URL.Path == "/v2/fixture/blobs/"+digest {
					w.Header().Set("Content-Type", "application/octet-stream")
					_, _ = w.Write(data)
					return
				}
			}
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	dir := t.TempDir()
	certificate := filepath.Join(dir, "registry-ca.pem")
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", certificate)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := liveCapability(t, "container.scan")
	for tag, image := range images {
		path := filepath.Join(dir, tag+".tar")
		image.archive(t, path)
		layout := filepath.Join(dir, tag+"-layout")
		image.layout(t, layout)
		for _, target := range []string{path, layout, "registry.cybot.invalid:" + port + "/fixture:" + tag} {
			r, err := c.Run(context.Background(), liveRequest(target), d)
			if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 2 || r.Status == "partial" {
				t.Fatalf("container source failed (%s): %+v %v", tag, r, err)
			}
			if tag == "negative" && len(r.Findings) != 0 {
				t.Fatalf("nonvulnerable container control matched: %+v", r.Findings)
			}
			if tag == "positive" {
				for _, tool := range []string{"trivy", "grype"} {
					found := false
					for _, finding := range r.Findings {
						found = found || strings.HasPrefix(finding.ID, tool+":")
					}
					if !found {
						t.Fatal("container scanner missed vulnerable layer", tool)
					}
				}
			}
		}
	}
	broken := filepath.Join(dir, "invalid.tar")
	if err := os.WriteFile(broken, []byte("not an image archive"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := c.Run(context.Background(), liveRequest(broken), d)
	if err == nil && len(r.Errors) == 0 && r.Status != "partial" {
		t.Fatal("invalid image archive reported clean")
	}
	certifyOperation(t, "grype", "container.scan", []operationCase{
		passedCase("positive", "Both scanners detect vulnerable npm layers in Docker archives, OCI layout directories and a TLS-verified loopback registry."),
		passedCase("negative", "All three source modes scan a nonvulnerable control layer without findings."),
		passedCase("failure", "An invalid image archive fails explicitly."),
	})
}
