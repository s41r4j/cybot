package capability

// Local-read operations must not start downloading dependencies or checking
// for product updates merely because the native host has network access.
func toolEnvironment(tool string) []string {
	switch tool {
	case "gosec":
		return []string{"GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOTELEMETRY=off"}
	case "semgrep":
		return []string{"SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0"}
	case "syft":
		return []string{"SYFT_CHECK_FOR_APP_UPDATE=false"}
	case "grype":
		return []string{"GRYPE_CHECK_FOR_APP_UPDATE=false", "GRYPE_DB_AUTO_UPDATE=false"}
	default:
		return nil
	}
}
