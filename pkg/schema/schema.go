// Package schema contains the stable, integration-facing CYBOT data model.
package schema

import (
	"encoding/json"
	"time"
)

type Argument struct {
	Name        string `json:"name" yaml:"name"`
	Type        string `json:"type" yaml:"type"`
	Required    bool   `json:"required" yaml:"required"`
	Description string `json:"description" yaml:"description"`
	Default     any    `json:"default,omitempty" yaml:"default,omitempty"`
}
type Example struct {
	Description string          `json:"description" yaml:"description"`
	Command     string          `json:"command,omitempty" yaml:"command,omitempty"`
	Input       json.RawMessage `json:"input,omitempty" yaml:"input,omitempty"`
	Output      json.RawMessage `json:"output,omitempty" yaml:"output,omitempty"`
}
type Documentation struct {
	Description         string     `json:"description" yaml:"description"`
	Purpose             string     `json:"purpose" yaml:"purpose"`
	Arguments           []Argument `json:"arguments" yaml:"arguments"`
	Examples            []Example  `json:"examples" yaml:"examples"`
	ExpectedOutput      string     `json:"expected_output" yaml:"expected_output"`
	OutputSchema        string     `json:"output_schema" yaml:"output_schema"`
	Limitations         []string   `json:"limitations" yaml:"limitations"`
	RequiredPermissions []string   `json:"required_permissions" yaml:"required_permissions"`
	RelatedCommands     []string   `json:"related_commands" yaml:"related_commands"`
	CommonMistakes      []string   `json:"common_mistakes" yaml:"common_mistakes"`
	BestPractices       []string   `json:"best_practices" yaml:"best_practices"`
}

type Skill struct {
	ID            string        `json:"id" yaml:"id"`
	Title         string        `json:"title" yaml:"title"`
	Description   string        `json:"description" yaml:"description"`
	Purpose       string        `json:"purpose" yaml:"purpose"`
	Tags          []string      `json:"tags,omitempty" yaml:"tags,omitempty"`
	Category      string        `json:"category" yaml:"category"`
	Steps         []Step        `json:"steps" yaml:"steps"`
	Requirements  []string      `json:"requirements,omitempty" yaml:"requirements,omitempty"`
	References    []string      `json:"references,omitempty" yaml:"references,omitempty"`
	Confidence    float64       `json:"confidence" yaml:"confidence"`
	Version       string        `json:"version" yaml:"version"`
	Author        string        `json:"author" yaml:"author"`
	Documentation Documentation `json:"documentation" yaml:"documentation"`
	Content       string        `json:"content,omitempty" yaml:"content,omitempty"`
}
type Step struct {
	Capability string          `json:"capability" yaml:"capability"`
	Input      json.RawMessage `json:"input,omitempty" yaml:"input,omitempty"`
}

type Tool struct {
	ID              string          `json:"id" yaml:"id"`
	Title           string          `json:"title" yaml:"title"`
	Description     string          `json:"description" yaml:"description"`
	Purpose         string          `json:"purpose" yaml:"purpose"`
	Version         string          `json:"version" yaml:"version"`
	Kind            string          `json:"kind" yaml:"kind"`
	Binary          string          `json:"binary,omitempty" yaml:"binary,omitempty"`
	DockerImage     string          `json:"docker_image,omitempty" yaml:"docker_image,omitempty"`
	SupportedOS     []string        `json:"supported_os,omitempty" yaml:"supported_os,omitempty"`
	WritablePaths   []string        `json:"writable_paths,omitempty" yaml:"writable_paths,omitempty"`
	InputSchema     json.RawMessage `json:"input_schema" yaml:"input_schema"`
	OutputSchema    json.RawMessage `json:"output_schema" yaml:"output_schema"`
	HealthCheck     []string        `json:"health_check,omitempty" yaml:"health_check,omitempty"`
	Documentation   Documentation   `json:"documentation" yaml:"documentation"`
	SourceURL       string          `json:"source_url" yaml:"source_url"`
	License         string          `json:"license" yaml:"license"`
	Capabilities    []string        `json:"capabilities" yaml:"capabilities"`
	DefaultArgs     []string        `json:"default_args" yaml:"default_args"`
	OutputFormat    string          `json:"output_format" yaml:"output_format"`
	Parser          string          `json:"parser" yaml:"parser"`
	Risk            string          `json:"risk" yaml:"risk"`
	RequiresNetwork bool            `json:"requires_network" yaml:"requires_network"`
}

type Source struct {
	ID           string `json:"id" yaml:"id"`
	Title        string `json:"title" yaml:"title"`
	URL          string `json:"url" yaml:"url"`
	Kind         string `json:"kind" yaml:"kind"`
	Trust        string `json:"trust" yaml:"trust"`
	License      string `json:"license" yaml:"license"`
	ImportFormat string `json:"import_format" yaml:"import_format"`
	Description  string `json:"description" yaml:"description"`
}

type DecisionNode struct {
	ID        string `json:"id" yaml:"id"`
	Action    string `json:"action" yaml:"action"`
	Condition string `json:"condition" yaml:"condition"`
	OnSuccess string `json:"on_success,omitempty" yaml:"on_success,omitempty"`
	OnFailure string `json:"on_failure,omitempty" yaml:"on_failure,omitempty"`
	Terminal  bool   `json:"terminal,omitempty" yaml:"terminal,omitempty"`
}
type ToolChoice struct {
	ToolID       string `json:"tool_id" yaml:"tool_id"`
	SelectedWhen string `json:"selected_when" yaml:"selected_when"`
	SkipWhen     string `json:"skip_when" yaml:"skip_when"`
	Reason       string `json:"reason" yaml:"reason"`
}
type CapabilityDefinition struct {
	ID                  string          `json:"id" yaml:"id"`
	Title               string          `json:"title" yaml:"title"`
	Version             string          `json:"version" yaml:"version"`
	Category            string          `json:"category" yaml:"category"`
	Stability           string          `json:"stability" yaml:"stability"`
	Implementation      string          `json:"implementation,omitempty" yaml:"implementation,omitempty"`
	Validation          string          `json:"validation,omitempty" yaml:"validation,omitempty"`
	ResourceScopes      []string        `json:"resource_scopes,omitempty" yaml:"resource_scopes,omitempty"`
	Documentation       Documentation   `json:"documentation" yaml:"documentation"`
	InputSchema         json.RawMessage `json:"input_schema" yaml:"input_schema"`
	OutputSchema        json.RawMessage `json:"output_schema" yaml:"output_schema"`
	Workflow            []DecisionNode  `json:"workflow" yaml:"workflow"`
	ToolChoices         []ToolChoice    `json:"tool_choices" yaml:"tool_choices"`
	Assumptions         []string        `json:"assumptions" yaml:"assumptions"`
	VerificationSteps   []string        `json:"verification_steps" yaml:"verification_steps"`
	RelatedCapabilities []string        `json:"related_capabilities" yaml:"related_capabilities"`
	NextCapabilities    []string        `json:"next_capabilities" yaml:"next_capabilities"`
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Result struct {
	Warnings                []string   `json:"warnings,omitempty"`
	Observations            []string   `json:"observations,omitempty"`
	RunID                   string     `json:"run_id"`
	Capability              string     `json:"capability"`
	Target                  string     `json:"target,omitempty"`
	Status                  string     `json:"status"`
	Summary                 string     `json:"summary"`
	Confidence              float64    `json:"confidence"`
	Assets                  []Asset    `json:"assets"`
	Services                []Service  `json:"services"`
	Endpoints               []Endpoint `json:"endpoints"`
	Findings                []Finding  `json:"findings"`
	Evidence                []Evidence `json:"evidence"`
	Errors                  []RunError `json:"errors"`
	Decisions               []Decision `json:"decisions"`
	Assumptions             []string   `json:"assumptions"`
	VerificationRecommended []string   `json:"verification_recommended"`
	NextCapabilities        []string   `json:"next_capabilities"`
	RelatedWorkflows        []string   `json:"related_workflows"`
	PossibleFalsePositives  []string   `json:"possible_false_positives"`
	StartedAt               time.Time  `json:"started_at"`
	FinishedAt              time.Time  `json:"finished_at"`
}
type Decision struct {
	Stage    string          `json:"stage"`
	Selected string          `json:"selected"`
	Reason   string          `json:"reason"`
	Skipped  []SkippedOption `json:"skipped"`
}
type SkippedOption struct {
	Option string `json:"option"`
	Reason string `json:"reason"`
}
type Asset struct {
	Value      string  `json:"value"`
	Type       string  `json:"type"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"`
}
type Service struct {
	Host       string  `json:"host"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Technology string  `json:"technology,omitempty"`
	Confidence float64 `json:"confidence"`
}
type Endpoint struct {
	URL        string   `json:"url"`
	Method     string   `json:"method,omitempty"`
	Status     int      `json:"status,omitempty"`
	Technology []string `json:"technology"`
}
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Confidence  float64  `json:"confidence"`
	Risk        string   `json:"risk,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}
type Evidence struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Path      string            `json:"path,omitempty"`
	SHA256    string            `json:"sha256"`
	MediaType string            `json:"media_type,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	Metadata  map[string]string `json:"metadata"`
}
type RunError struct {
	Tool      string `json:"tool,omitempty"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}
type Report struct {
	ID          string    `json:"id" yaml:"id"`
	RunID       string    `json:"run_id" yaml:"run_id"`
	Format      string    `json:"format" yaml:"format"`
	GeneratedAt time.Time `json:"generated_at" yaml:"generated_at"`
	Result      Result    `json:"result" yaml:"result"`
}
type Workflow struct {
	ID           string   `json:"id" yaml:"id"`
	Description  string   `json:"description" yaml:"description"`
	Capabilities []string `json:"capabilities" yaml:"capabilities"`
	Status       string   `json:"status" yaml:"status"`
	Next         string   `json:"next" yaml:"next"`
}
type PlanStage struct {
	Order        int      `json:"order" yaml:"order"`
	ID           string   `json:"id" yaml:"id"`
	Action       string   `json:"action" yaml:"action"`
	Condition    string   `json:"condition" yaml:"condition"`
	Tools        []string `json:"tools" yaml:"tools"`
	Parallel     bool     `json:"parallel" yaml:"parallel"`
	Verification string   `json:"verification" yaml:"verification"`
}
type ExecutionPlan struct {
	Warnings         []string        `json:"warnings,omitempty" yaml:"warnings,omitempty"`
	ToolAvailability string          `json:"tool_availability" yaml:"tool_availability"`
	Capability       string          `json:"capability" yaml:"capability"`
	Target           string          `json:"target,omitempty" yaml:"target,omitempty"`
	DeterministicKey string          `json:"deterministic_key" yaml:"deterministic_key"`
	PolicyDecision   string          `json:"policy_decision" yaml:"policy_decision"`
	RequiresApproval bool            `json:"requires_approval" yaml:"requires_approval"`
	Executable       bool            `json:"executable" yaml:"executable"`
	Stages           []PlanStage     `json:"stages" yaml:"stages"`
	SelectedTools    []string        `json:"selected_tools" yaml:"selected_tools"`
	SkippedTools     []SkippedOption `json:"skipped_tools" yaml:"skipped_tools"`
	Assumptions      []string        `json:"assumptions" yaml:"assumptions"`
	ExpectedSchema   string          `json:"expected_schema" yaml:"expected_schema"`
}
type AuditEvent struct {
	Timestamp  time.Time `json:"timestamp" yaml:"timestamp"`
	Level      string    `json:"level" yaml:"level"`
	Event      string    `json:"event" yaml:"event"`
	RunID      string    `json:"run_id,omitempty" yaml:"run_id,omitempty"`
	Capability string    `json:"capability,omitempty" yaml:"capability,omitempty"`
	Target     string    `json:"target,omitempty" yaml:"target,omitempty"`
	Status     string    `json:"status,omitempty" yaml:"status,omitempty"`
	Message    string    `json:"message" yaml:"message"`
}
type RunRequest struct {
	Capability string          `json:"capability" yaml:"capability"`
	Target     string          `json:"target,omitempty" yaml:"target,omitempty"`
	Input      json.RawMessage `json:"input" yaml:"input"`
	Approved   bool            `json:"approved" yaml:"approved"`
	RunID      string          `json:"-" yaml:"-"`
}

type VulnerabilityPattern struct {
	ID             string   `json:"id" yaml:"id"`
	Title          string   `json:"title" yaml:"title"`
	Capability     string   `json:"capability" yaml:"capability"`
	Triggers       []string `json:"triggers" yaml:"triggers"`
	Detection      []string `json:"detection" yaml:"detection"`
	Payloads       []string `json:"payloads" yaml:"payloads"`
	Bypass         []string `json:"bypass" yaml:"bypass"`
	ChainTemplates []string `json:"chain_templates" yaml:"chain_templates"`
	FalsePositives []string `json:"false_positives" yaml:"false_positives"`
}

type PlatformChain struct {
	ID          string          `json:"id" yaml:"id"`
	Title       string          `json:"title" yaml:"title"`
	Category    string          `json:"category" yaml:"category"`
	Description string          `json:"description" yaml:"description"`
	References  []string        `json:"references,omitempty" yaml:"references,omitempty"`
	Chains      []PlatformPhase `json:"chains" yaml:"chains"`
	KnownCVEs   []string        `json:"known_cves,omitempty" yaml:"known_cves,omitempty"`
	ToolMapping []string        `json:"tool_mapping" yaml:"tool_mapping"`
}

type PlatformPhase struct {
	Phase      string   `json:"phase" yaml:"phase"`
	Techniques []string `json:"techniques" yaml:"techniques"`
}

type VulnerabilityCatalog struct {
	Patterns []VulnerabilityPattern `json:"patterns" yaml:"patterns"`
}
type PlatformCatalog struct {
	Platforms []PlatformChain `json:"platforms" yaml:"platforms"`
}

type ClassificationRequest struct {
	URL    string `json:"url" yaml:"url"`
	Method string `json:"method,omitempty" yaml:"method,omitempty"`
}

type ClassificationResult struct {
	URL        string                `json:"url" yaml:"url"`
	Matches    []ClassificationMatch `json:"matches" yaml:"matches"`
	Confidence float64               `json:"confidence" yaml:"confidence"`
}

type ClassificationMatch struct {
	PatternID  string  `json:"pattern_id" yaml:"pattern_id"`
	Capability string  `json:"capability" yaml:"capability"`
	Confidence float64 `json:"confidence" yaml:"confidence"`
	Reason     string  `json:"reason" yaml:"reason"`
}

type ValidationRequest struct {
	FindingText string `json:"finding_text" yaml:"finding_text"`
	Platform    string `json:"platform,omitempty" yaml:"platform,omitempty"`
}

type ValidationQuestion struct {
	Number    int    `json:"number" yaml:"number"`
	Question  string `json:"question" yaml:"question"`
	Verdict   string `json:"verdict" yaml:"verdict"`
	Reasoning string `json:"reasoning" yaml:"reasoning"`
}

type ValidationResult struct {
	Verdict   string               `json:"verdict" yaml:"verdict"`
	Questions []ValidationQuestion `json:"questions" yaml:"questions"`
	Summary   string               `json:"summary" yaml:"summary"`
}

type Engagement struct {
	Warnings  []string  `json:"warnings,omitempty" yaml:"warnings,omitempty"`
	Name      string    `json:"name" yaml:"name"`
	BasePath  string    `json:"base_path" yaml:"base_path"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	Files     []string  `json:"files" yaml:"files"`
}

type MemoryEntry struct {
	Target       string    `json:"target" yaml:"target"`
	Capability   string    `json:"capability" yaml:"capability"`
	Status       string    `json:"status" yaml:"status"`
	Findings     int       `json:"findings" yaml:"findings"`
	LastRunAt    time.Time `json:"last_run_at" yaml:"last_run_at"`
	EstimateSkip bool      `json:"estimate_skip" yaml:"estimate_skip"`
	SkipReason   string    `json:"skip_reason,omitempty" yaml:"skip_reason,omitempty"`
}

type SeverityMapping struct {
	ID       string         `json:"id" yaml:"id"`
	Name     string         `json:"name" yaml:"name"`
	Features map[string]any `json:"features" yaml:"features"`
}

type CVE struct {
	ID           string   `json:"id" yaml:"id"`
	Year         string   `json:"year" yaml:"year"`
	Title        string   `json:"title" yaml:"title"`
	Description  string   `json:"description" yaml:"description"`
	Severity     Severity `json:"severity" yaml:"severity"`
	CVSS         float64  `json:"cvss" yaml:"cvss"`
	CWE          string   `json:"cwe,omitempty" yaml:"cwe,omitempty"`
	Affected     []string `json:"affected,omitempty" yaml:"affected,omitempty"`
	ExploitKnown bool     `json:"exploit_known" yaml:"exploit_known"`
	Keywords     []string `json:"keywords" yaml:"keywords"`
	Capabilities []string `json:"capabilities" yaml:"capabilities"`
	References   []string `json:"references" yaml:"references"`
}

type CVECatalog struct {
	CVEs []CVE `json:"cves" yaml:"cves"`
}

type AttackTechnique struct {
	ID                    string   `json:"id" yaml:"id"`
	Name                  string   `json:"name" yaml:"name"`
	Tactic                string   `json:"tactic" yaml:"tactic"`
	Description           string   `json:"description" yaml:"description"`
	DetectionCapabilities []string `json:"detection_capabilities" yaml:"detection_capabilities"`
	ActionCapabilities    []string `json:"action_capabilities" yaml:"action_capabilities"`
}

type AttackCatalog struct {
	Techniques []AttackTechnique `json:"techniques" yaml:"techniques"`
}
