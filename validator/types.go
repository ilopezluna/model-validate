package validator

import "net/http"

// Policy controls how SHOULD-level findings are handled.
type Policy string

const (
	// PolicyDefault reports MUST findings as errors and SHOULD findings as warnings.
	PolicyDefault Policy = "default"

	// PolicyStrict reports both MUST and SHOULD findings as errors.
	PolicyStrict Policy = "strict"

	// PolicyMustOnly reports only MUST findings and ignores SHOULD findings.
	PolicyMustOnly Policy = "must-only"
)

// Severity is the reported level of a validation finding.
type Severity string

const (
	// SeverityError marks a finding that makes the artifact non-compliant.
	SeverityError Severity = "error"

	// SeverityWarning marks a finding that does not fail default policy.
	SeverityWarning Severity = "warning"
)

// Options configures library validation.
type Options struct {
	// Policy controls how SHOULD-level findings are handled.
	Policy Policy

	// PlainHTTP uses HTTP instead of HTTPS for remote registry access.
	PlainHTTP bool

	// DockerConfigPath overrides the Docker config file used for auth lookup.
	DockerConfigPath string

	// Username provides explicit basic auth credentials.
	Username string

	// Password provides the password for explicit basic auth.
	Password string

	// RegistryToken provides an explicit bearer token.
	RegistryToken string

	// HTTPClient overrides the HTTP client used for remote access.
	HTTPClient *http.Client
}

// Finding describes a single validation issue.
type Finding struct {
	Code             string   `json:"code"`
	Severity         Severity `json:"severity"`
	Message          string   `json:"message"`
	Path             string   `json:"path,omitempty"`
	DescriptorDigest string   `json:"descriptorDigest,omitempty"`
	SpecRef          string   `json:"specRef,omitempty"`
}

// Result is the stable validation result shared by the library and the CLI.
type Result struct {
	Reference      string    `json:"reference"`
	ResolvedDigest string    `json:"resolvedDigest,omitempty"`
	Compliant      bool      `json:"compliant"`
	Policy         Policy    `json:"policy"`
	Findings       []Finding `json:"findings"`
	ErrorCount     int       `json:"errorCount"`
	WarningCount   int       `json:"warningCount"`
}
