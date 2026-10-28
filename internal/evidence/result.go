package evidence

import (
	"encoding/json"
	"github.com/s41r4j/cybot/pkg/schema"
)

func RedactText(text string) string { return sanitizeSecrets(text) }

// RedactResult removes recognized credentials before history, logs and reports.
// Identifiers, hashes and schema fields are preserved.
func RedactResult(r *schema.Result) {
	r.Target = sanitizeSecrets(r.Target)
	r.Summary = sanitizeSecrets(r.Summary)
	for i := range r.Findings {
		r.Findings[i].Title = sanitizeSecrets(r.Findings[i].Title)
		r.Findings[i].Description = sanitizeSecrets(r.Findings[i].Description)
	}
	for i := range r.Assets {
		r.Assets[i].Value = sanitizeSecrets(r.Assets[i].Value)
	}
	for i := range r.Endpoints {
		r.Endpoints[i].URL = SanitizeURL(r.Endpoints[i].URL)
	}
	for i := range r.Errors {
		r.Errors[i].Message = sanitizeSecrets(r.Errors[i].Message)
	}
	for i := range r.Decisions {
		r.Decisions[i].Reason = sanitizeSecrets(r.Decisions[i].Reason)
	}
	for i := range r.Evidence {
		for k, v := range r.Evidence[i].Metadata {
			r.Evidence[i].Metadata[k] = sanitizeSecrets(v)
		}
	}
	for i := range r.Warnings {
		r.Warnings[i] = sanitizeSecrets(r.Warnings[i])
	}
	for i := range r.Observations {
		if json.Valid([]byte(r.Observations[i])) {
			if b, err := DefaultHygieneRules.SanitizeJSON([]byte(r.Observations[i])); err == nil {
				r.Observations[i] = string(b)
			}
		} else {
			r.Observations[i] = sanitizeSecrets(r.Observations[i])
		}
	}
}

func RedactAudit(e *schema.AuditEvent) {
	e.Target = sanitizeSecrets(e.Target)
	e.Message = sanitizeSecrets(e.Message)
}

type redactedError struct{ cause error }

func (e redactedError) Error() string { return sanitizeSecrets(e.cause.Error()) }
func (e redactedError) Unwrap() error { return e.cause }
func RedactError(err error) error {
	if err == nil {
		return nil
	}
	return redactedError{cause: err}
}
