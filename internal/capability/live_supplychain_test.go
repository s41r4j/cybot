package capability

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestLiveSupplyChainVulnerabilities(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_SUPPLYCHAIN") != "1" {
		t.Skip("requires isolated supply-chain toolbox with a pinned database")
	}
	d := liveDeps(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	write := func(version string) {
		t.Helper()
		lock := fmt.Sprintf(`{"name":"fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0","dependencies":{"lodash":%q}},"node_modules/lodash":{"name":"lodash","version":%q}}}`, version, version)
		if err := os.WriteFile(path, []byte(lock), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := liveCapability(t, "dependency.scan")
	write("4.17.20")
	r, err := c.Run(context.Background(), liveRequest(dir), d)
	if err != nil || len(r.Errors) != 0 || len(r.Findings) == 0 || len(r.Evidence) != 2 || r.Status == "partial" {
		t.Fatalf("known vulnerable package missed: %+v %v", r, err)
	}
	validateFixtureResult(t, r)
	for _, tool := range []string{"trivy", "grype"} {
		found := false
		for _, finding := range r.Findings {
			found = found || strings.HasPrefix(finding.ID, tool+":")
		}
		if !found {
			t.Fatal("dependency scanner missed vulnerable package", tool)
		}
	}
	// Deliberately synthetic version outside the known vulnerable range. No
	// package is downloaded or claimed to exist in a public package registry.
	write("9999.0.0")
	r, err = c.Run(context.Background(), liveRequest(dir), d)
	if err != nil || len(r.Errors) != 0 || len(r.Findings) != 0 || r.Status == "partial" {
		t.Fatalf("nonvulnerable control failed: %+v %v", r, err)
	}
	requireToolFailure(t, d, "trivy", []string{"filesystem", "--cybot-invalid-fixture-option"})
	requireToolFailure(t, d, "grype", []string{"--cybot-invalid-fixture-option"})
	cases := []operationCase{
		passedCase("positive", "Both pinned offline databases identify vulnerable lodash 4.17.20 from a local lockfile."),
		passedCase("negative", "A synthetic package version outside the vulnerable range produces no vulnerability finding."),
		passedCase("failure", "Both real scanners reject invalid scan options."),
	}
	certifyOperation(t, "trivy", "", cases)
	certifyOperation(t, "grype", "dependency.scan", cases)
}

func TestLiveSupplyChainCloudConfig(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_SUPPLYCHAIN") != "1" {
		t.Skip("requires isolated supply-chain toolbox")
	}
	d := liveDeps(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	write := func(action, resource string) {
		t.Helper()
		source := fmt.Sprintf(`resource "aws_iam_policy" "fixture" {
  name = "cybot-local-fixture"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = [%q], Resource = [%q] }]
  })
}
`, action, resource)
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := liveCapability(t, "cloud.review")
	write("*", "*")
	r, err := c.Run(context.Background(), liveRequest(dir), d)
	if err != nil || len(r.Errors) != 0 || len(r.Findings) == 0 || r.Status == "partial" {
		t.Fatalf("wildcard IAM policy was not detected: %+v %v", r, err)
	}
	validateFixtureResult(t, r)
	write("s3:GetObject", "arn:aws:s3:::cybot-fixture/specific-object")
	r, err = c.Run(context.Background(), liveRequest(dir), d)
	if err != nil || len(r.Errors) != 0 || len(r.Findings) != 0 || r.Status == "partial" {
		t.Fatalf("scoped IAM policy did not pass control: %+v %v", r, err)
	}
	broken := c
	broken.steps = append([]toolStep{}, c.steps...)
	broken.steps[0].Args = func(string, schema.RunRequest) []string {
		return []string{"config", "--cybot-invalid-fixture-option"}
	}
	r, err = broken.Run(context.Background(), liveRequest(dir), d)
	if err == nil && r.Status != "partial" && len(r.Errors) == 0 {
		t.Fatal("invalid configuration scan reported clean")
	}
	certifyOperation(t, "trivy", "cloud.review", []operationCase{
		passedCase("positive", "Embedded Terraform checks detect a wildcard administrative IAM policy locally."),
		passedCase("negative", "A least-privilege IAM policy passes the same embedded checks."),
		passedCase("failure", "Invalid required scanner configuration fails the capability."),
	})
}
