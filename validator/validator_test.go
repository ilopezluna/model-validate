package validator_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ilopezluna/model-validate/internal/testregistry"
	"github.com/ilopezluna/model-validate/validator"
	modelspecv1 "github.com/modelpack/model-spec/specs-go/v1"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestValidateReferenceValidArtifact(t *testing.T) {
	t.Parallel()

	server := testregistry.New()
	t.Cleanup(server.Close)

	reference := publishValidArtifact(t, server, "models/demo", "good")

	result, err := validator.ValidateReference(
		context.Background(),
		reference,
		validator.Options{
			PlainHTTP: true,
		},
	)
	if err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}

	if !result.Compliant {
		t.Fatalf("expected compliant result, got %#v", result)
	}
	if result.ErrorCount != 0 || result.WarningCount != 0 {
		t.Fatalf("unexpected counts: %#v", result)
	}
}

func TestValidateReferenceRootIndex(t *testing.T) {
	t.Parallel()

	server := testregistry.New()
	t.Cleanup(server.Close)

	configDescriptor := server.AddBlob(
		"models/demo",
		modelspecv1.MediaTypeModelConfig,
		validConfigBody([]string{randomDigest(t).String()}),
	)
	indexBody := testregistry.JSON(map[string]any{
		"schemaVersion": 2,
		"mediaType":     ocispec.MediaTypeImageIndex,
		"manifests": []map[string]any{
			descriptorMap(configDescriptor, nil, ocispec.MediaTypeImageManifest),
		},
	})
	server.AddManifest(
		"models/demo",
		"index",
		ocispec.MediaTypeImageIndex,
		indexBody,
	)

	result, err := validator.ValidateReference(
		context.Background(),
		server.Reference("models/demo", "index"),
		validator.Options{
			PlainHTTP: true,
		},
	)
	if err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}

	if result.Compliant {
		t.Fatalf("expected non-compliant result, got %#v", result)
	}
	assertFindingCode(t, result, "root-not-manifest")
}

func TestValidateReferenceInvalidArtifactType(t *testing.T) {
	t.Parallel()

	server := testregistry.New()
	t.Cleanup(server.Close)

	reference := publishArtifact(t, server, publishOptions{
		Repository:   "models/demo",
		Tag:          "bad-artifact-type",
		ArtifactType: "application/example.invalid",
	})

	result, err := validator.ValidateReference(
		context.Background(),
		reference,
		validator.Options{
			PlainHTTP: true,
		},
	)
	if err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}

	assertFindingCode(t, result, "invalid-artifact-type")
	if result.ErrorCount == 0 {
		t.Fatalf("expected an error finding, got %#v", result)
	}
}

func TestValidateReferenceInvalidConfigMediaType(t *testing.T) {
	t.Parallel()

	server := testregistry.New()
	t.Cleanup(server.Close)

	reference := publishArtifact(t, server, publishOptions{
		Repository:      "models/demo",
		Tag:             "bad-config-media-type",
		ConfigMediaType: "application/example.config+json",
	})

	result, err := validator.ValidateReference(
		context.Background(),
		reference,
		validator.Options{
			PlainHTTP: true,
		},
	)
	if err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}

	assertFindingCode(t, result, "invalid-config-descriptor")
}

func TestValidateReferenceInvalidConfigJSON(t *testing.T) {
	t.Parallel()

	server := testregistry.New()
	t.Cleanup(server.Close)

	reference := publishArtifact(t, server, publishOptions{
		Repository: "models/demo",
		Tag:        "bad-config-json",
		ConfigBody: []byte(`{"modelfs":{"type":"layers","diffIds":[1]}}`),
	})

	result, err := validator.ValidateReference(
		context.Background(),
		reference,
		validator.Options{
			PlainHTTP: true,
		},
	)
	if err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}

	assertFindingCode(t, result, "invalid-model-config")
}

func TestValidateReferenceDiffIDCountMismatch(t *testing.T) {
	t.Parallel()

	server := testregistry.New()
	t.Cleanup(server.Close)

	reference := publishArtifact(t, server, publishOptions{
		Repository: "models/demo",
		Tag:        "diffid-mismatch",
		DiffIDs: []string{
			randomDigest(t).String(),
		},
	})

	result, err := validator.ValidateReference(
		context.Background(),
		reference,
		validator.Options{
			PlainHTTP: true,
		},
	)
	if err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}

	assertFindingCode(t, result, "diffid-count-mismatch")
}

func TestValidateReferenceUnknownLayerMediaTypePolicies(t *testing.T) {
	t.Parallel()

	server := testregistry.New()
	t.Cleanup(server.Close)

	reference := publishArtifact(t, server, publishOptions{
		Repository: "models/demo",
		Tag:        "unknown-media-type",
		LayerMediaTypes: []string{
			modelspecv1.MediaTypeModelWeight,
			"application/example.layer",
		},
	})

	testCases := []struct {
		name         string
		policy       validator.Policy
		errorCount   int
		warningCount int
		wantFinding  bool
	}{
		{
			name:         "default",
			policy:       validator.PolicyDefault,
			errorCount:   0,
			warningCount: 1,
			wantFinding:  true,
		},
		{
			name:         "strict",
			policy:       validator.PolicyStrict,
			errorCount:   1,
			warningCount: 0,
			wantFinding:  true,
		},
		{
			name:         "must-only",
			policy:       validator.PolicyMustOnly,
			errorCount:   0,
			warningCount: 0,
			wantFinding:  false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := validator.ValidateReference(
				context.Background(),
				reference,
				validator.Options{
					PlainHTTP: true,
					Policy:    tc.policy,
				},
			)
			if err != nil {
				t.Fatalf("ValidateReference() error = %v", err)
			}

			if result.ErrorCount != tc.errorCount ||
				result.WarningCount != tc.warningCount {
				t.Fatalf("unexpected counts: %#v", result)
			}

			hasFinding := containsFinding(result, "unknown-layer-media-type")
			if hasFinding != tc.wantFinding {
				t.Fatalf("finding presence = %t, want %t", hasFinding, tc.wantFinding)
			}
		})
	}
}

func TestValidateReferenceMissingLayerBlob(t *testing.T) {
	t.Parallel()

	server := testregistry.New()
	t.Cleanup(server.Close)

	reference, deletedDigest := publishArtifactDeletingLayer(
		t,
		server,
		"models/demo",
		"missing-layer",
		1,
	)

	result, err := validator.ValidateReference(
		context.Background(),
		reference,
		validator.Options{
			PlainHTTP: true,
		},
	)
	if err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}

	assertFindingCode(t, result, "missing-blob")
	assertFindingDigest(t, result, deletedDigest.String())
}

func TestValidateReferenceInvalidAnnotations(t *testing.T) {
	t.Parallel()

	server := testregistry.New()
	t.Cleanup(server.Close)

	reference := publishArtifact(t, server, publishOptions{
		Repository: "models/demo",
		Tag:        "bad-annotations",
		LayerAnnotations: []map[string]string{
			{
				"org.cncf.model.filepath":                "",
				"org.cncf.model.file.mediatype.untested": "maybe",
				"org.cncf.model.file.metadata+json":      `{"name":`,
			},
			nil,
		},
	})

	result, err := validator.ValidateReference(
		context.Background(),
		reference,
		validator.Options{
			PlainHTTP: true,
		},
	)
	if err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}

	if countFindings(result, "invalid-annotation") < 3 {
		t.Fatalf("expected three annotation findings, got %#v", result)
	}
}

func TestValidateReferenceUsesDockerConfigAuth(t *testing.T) {
	t.Parallel()

	server := testregistry.New()
	t.Cleanup(server.Close)
	server.SetBasicAuth("demo", "secret")

	reference := publishValidArtifact(t, server, "private/demo", "secure")

	configPath := writeDockerConfig(
		t,
		server.Host(),
		"demo",
		"secret",
	)

	result, err := validator.ValidateReference(
		context.Background(),
		reference,
		validator.Options{
			PlainHTTP:        true,
			DockerConfigPath: configPath,
		},
	)
	if err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}

	if !result.Compliant {
		t.Fatalf("expected compliant result, got %#v", result)
	}
}

func TestValidateReferenceUsesCredentialHelper(t *testing.T) {
	server := testregistry.New()
	t.Cleanup(server.Close)
	server.SetBasicAuth("helper-user", "helper-pass")

	reference := publishValidArtifact(t, server, "private/helper", "secure")

	configPath := writeCredentialHelperConfig(t, server.Host())

	result, err := validator.ValidateReference(
		context.Background(),
		reference,
		validator.Options{
			PlainHTTP:        true,
			DockerConfigPath: configPath,
		},
	)
	if err != nil {
		t.Fatalf("ValidateReference() error = %v", err)
	}

	if !result.Compliant {
		t.Fatalf("expected compliant result, got %#v", result)
	}
}

type publishOptions struct {
	Repository       string
	Tag              string
	ArtifactType     string
	ConfigMediaType  string
	ConfigBody       []byte
	DiffIDs          []string
	LayerMediaTypes  []string
	LayerAnnotations []map[string]string
}

func publishValidArtifact(
	t *testing.T,
	server *testregistry.Server,
	repository string,
	tag string,
) string {
	t.Helper()
	return publishArtifact(t, server, publishOptions{
		Repository: repository,
		Tag:        tag,
	})
}

func publishArtifact(
	t *testing.T,
	server *testregistry.Server,
	opts publishOptions,
) string {
	t.Helper()

	layerMediaTypes := opts.LayerMediaTypes
	if len(layerMediaTypes) == 0 {
		layerMediaTypes = []string{
			modelspecv1.MediaTypeModelWeight,
			modelspecv1.MediaTypeModelDoc,
		}
	}

	layerDescriptors := make([]ocispec.Descriptor, 0, len(layerMediaTypes))
	for index, mediaType := range layerMediaTypes {
		layerBody := []byte(fmt.Sprintf("layer-%d", index))
		layerDescriptor := server.AddBlob(opts.Repository, mediaType, layerBody)
		if index < len(opts.LayerAnnotations) && opts.LayerAnnotations[index] != nil {
			layerDescriptor.Annotations = opts.LayerAnnotations[index]
		}
		layerDescriptors = append(layerDescriptors, layerDescriptor)
	}

	diffIDs := opts.DiffIDs
	if len(diffIDs) == 0 {
		diffIDs = make([]string, 0, len(layerDescriptors))
		for _, descriptor := range layerDescriptors {
			diffIDs = append(diffIDs, descriptor.Digest.String())
		}
	}

	configBody := opts.ConfigBody
	if len(configBody) == 0 {
		configBody = validConfigBody(diffIDs)
	}

	configMediaType := opts.ConfigMediaType
	if configMediaType == "" {
		configMediaType = modelspecv1.MediaTypeModelConfig
	}
	configDescriptor := server.AddBlob(
		opts.Repository,
		configMediaType,
		configBody,
	)

	artifactType := opts.ArtifactType
	if artifactType == "" {
		artifactType = modelspecv1.ArtifactTypeModelManifest
	}

	layerMaps := make([]map[string]any, 0, len(layerDescriptors))
	for _, descriptor := range layerDescriptors {
		layerMaps = append(layerMaps, descriptorMap(descriptor, descriptor.Annotations, ""))
	}

	manifestBody := testregistry.JSON(map[string]any{
		"schemaVersion": 2,
		"mediaType":     ocispec.MediaTypeImageManifest,
		"artifactType":  artifactType,
		"config":        descriptorMap(configDescriptor, nil, configMediaType),
		"layers":        layerMaps,
	})
	server.AddManifest(
		opts.Repository,
		opts.Tag,
		ocispec.MediaTypeImageManifest,
		manifestBody,
	)

	return server.Reference(opts.Repository, opts.Tag)
}

func publishArtifactDeletingLayer(
	t *testing.T,
	server *testregistry.Server,
	repository string,
	tag string,
	deleteIndex int,
) (string, digest.Digest) {
	t.Helper()

	layerMediaTypes := []string{
		modelspecv1.MediaTypeModelWeight,
		modelspecv1.MediaTypeModelDoc,
	}
	layerDescriptors := make([]ocispec.Descriptor, 0, len(layerMediaTypes))
	for index, mediaType := range layerMediaTypes {
		layerDescriptor := server.AddBlob(
			repository,
			mediaType,
			[]byte(fmt.Sprintf("layer-%d", index)),
		)
		layerDescriptors = append(layerDescriptors, layerDescriptor)
	}

	configDescriptor := server.AddBlob(
		repository,
		modelspecv1.MediaTypeModelConfig,
		validConfigBody([]string{
			layerDescriptors[0].Digest.String(),
			layerDescriptors[1].Digest.String(),
		}),
	)

	layerMaps := make([]map[string]any, 0, len(layerDescriptors))
	for _, descriptor := range layerDescriptors {
		layerMaps = append(layerMaps, descriptorMap(descriptor, nil, ""))
	}

	manifestBody := testregistry.JSON(map[string]any{
		"schemaVersion": 2,
		"mediaType":     ocispec.MediaTypeImageManifest,
		"artifactType":  modelspecv1.ArtifactTypeModelManifest,
		"config":        descriptorMap(configDescriptor, nil, modelspecv1.MediaTypeModelConfig),
		"layers":        layerMaps,
	})
	server.AddManifest(
		repository,
		tag,
		ocispec.MediaTypeImageManifest,
		manifestBody,
	)
	server.DeleteBlob(repository, layerDescriptors[deleteIndex].Digest)

	return server.Reference(repository, tag), layerDescriptors[deleteIndex].Digest
}

func descriptorMap(
	descriptor ocispec.Descriptor,
	annotations map[string]string,
	mediaType string,
) map[string]any {
	if mediaType == "" {
		mediaType = descriptor.MediaType
	}

	result := map[string]any{
		"mediaType": mediaType,
		"digest":    descriptor.Digest.String(),
		"size":      descriptor.Size,
	}
	if len(annotations) != 0 {
		result["annotations"] = annotations
	}
	return result
}

func validConfigBody(diffIDs []string) []byte {
	return testregistry.JSON(map[string]any{
		"descriptor": map[string]any{
			"name":    "demo-model",
			"version": "1.0.0",
		},
		"config": map[string]any{
			"format":    "pt",
			"precision": "float16",
		},
		"modelfs": map[string]any{
			"type":    "layers",
			"diffIds": diffIDs,
		},
	})
}

func assertFindingCode(
	t *testing.T,
	result validator.Result,
	code string,
) {
	t.Helper()

	if !containsFinding(result, code) {
		t.Fatalf("missing finding %q in %#v", code, result)
	}
}

func assertFindingDigest(
	t *testing.T,
	result validator.Result,
	dgst string,
) {
	t.Helper()

	for _, finding := range result.Findings {
		if finding.DescriptorDigest == dgst {
			return
		}
	}

	t.Fatalf("missing descriptor digest %q in %#v", dgst, result)
}

func containsFinding(result validator.Result, code string) bool {
	for _, finding := range result.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func countFindings(result validator.Result, code string) int {
	count := 0
	for _, finding := range result.Findings {
		if finding.Code == code {
			count++
		}
	}
	return count
}

func randomDigest(t *testing.T) digest.Digest {
	t.Helper()
	return digest.FromString(t.Name() + "-" + strings.Repeat("x", 8))
}

func writeDockerConfig(
	t *testing.T,
	host string,
	username string,
	password string,
) string {
	t.Helper()

	configDir := t.TempDir()
	auth := base64.StdEncoding.EncodeToString(
		[]byte(username + ":" + password),
	)
	configPath := filepath.Join(configDir, "config.json")
	configBody := testregistry.JSON(map[string]any{
		"auths": map[string]any{
			host: map[string]any{
				"auth": auth,
			},
		},
	})
	if err := os.WriteFile(configPath, configBody, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return configPath
}

func writeCredentialHelperConfig(
	t *testing.T,
	host string,
) string {
	t.Helper()

	helperDir := t.TempDir()
	helperPath := filepath.Join(helperDir, "docker-credential-testhelper")
	helperBody := strings.Join([]string{
		"#!/bin/sh",
		"if [ \"$1\" = \"get\" ]; then",
		"  read server",
		"  printf '{\"Username\":\"helper-user\",\"Secret\":\"helper-pass\"}'",
		"  exit 0",
		"fi",
		"exit 1",
	}, "\n")
	if err := os.WriteFile(helperPath, []byte(helperBody), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	t.Setenv("PATH", helperDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	configBody := testregistry.JSON(map[string]any{
		"credHelpers": map[string]string{
			host: "testhelper",
		},
	})
	if err := os.WriteFile(configPath, configBody, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return configPath
}
