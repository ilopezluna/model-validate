package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ilopezluna/model-validate/internal/testregistry"
	modelspecv1 "github.com/modelpack/model-spec/specs-go/v1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestRunHumanOutput(t *testing.T) {
	t.Parallel()

	server := testregistry.New()
	t.Cleanup(server.Close)

	reference := publishArtifact(t, server, cliArtifactOptions{
		repository: "models/demo",
		tag:        "warn",
		layerMediaTypes: []string{
			modelspecv1.MediaTypeModelWeight,
			"application/example.layer",
		},
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run(
		context.Background(),
		[]string{"--plain-http", reference},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("exitCode = %d, stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS WITH WARNINGS") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "unknown-layer-media-type") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunJSONOutputFailure(t *testing.T) {
	t.Parallel()

	server := testregistry.New()
	t.Cleanup(server.Close)

	reference := publishArtifact(t, server, cliArtifactOptions{
		repository:   "models/demo",
		tag:          "fail",
		artifactType: "application/example.invalid",
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run(
		context.Background(),
		[]string{"--plain-http", "--output", "json", reference},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)

	if exitCode != 1 {
		t.Fatalf("exitCode = %d, stderr = %q", exitCode, stderr.String())
	}

	var payload struct {
		ErrorCount int `json:"errorCount"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.ErrorCount == 0 {
		t.Fatalf("expected JSON output with errors, got %q", stdout.String())
	}
}

func TestRunOperationalError(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run(
		context.Background(),
		[]string{"not-a-valid-reference"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)

	if exitCode != 2 {
		t.Fatalf("exitCode = %d, stderr = %q", exitCode, stderr.String())
	}
}

type cliArtifactOptions struct {
	repository      string
	tag             string
	artifactType    string
	layerMediaTypes []string
}

func publishArtifact(
	t *testing.T,
	server *testregistry.Server,
	opts cliArtifactOptions,
) string {
	t.Helper()

	layerMediaTypes := opts.layerMediaTypes
	if len(layerMediaTypes) == 0 {
		layerMediaTypes = []string{
			modelspecv1.MediaTypeModelWeight,
			modelspecv1.MediaTypeModelDoc,
		}
	}

	layerDescriptors := make([]map[string]any, 0, len(layerMediaTypes))
	diffIDs := make([]string, 0, len(layerMediaTypes))
	for index, mediaType := range layerMediaTypes {
		layerDescriptor := server.AddBlob(
			opts.repository,
			mediaType,
			[]byte{byte(index + 1)},
		)
		layerDescriptors = append(layerDescriptors, map[string]any{
			"mediaType": layerDescriptor.MediaType,
			"digest":    layerDescriptor.Digest.String(),
			"size":      layerDescriptor.Size,
		})
		diffIDs = append(diffIDs, layerDescriptor.Digest.String())
	}

	configDescriptor := server.AddBlob(
		opts.repository,
		modelspecv1.MediaTypeModelConfig,
		testregistry.JSON(map[string]any{
			"descriptor": map[string]any{
				"name": "cli-model",
			},
			"config": map[string]any{
				"format": "pt",
			},
			"modelfs": map[string]any{
				"type":    "layers",
				"diffIds": diffIDs,
			},
		}),
	)

	artifactType := opts.artifactType
	if artifactType == "" {
		artifactType = modelspecv1.ArtifactTypeModelManifest
	}

	server.AddManifest(
		opts.repository,
		opts.tag,
		ocispec.MediaTypeImageManifest,
		testregistry.JSON(map[string]any{
			"schemaVersion": 2,
			"mediaType":     ocispec.MediaTypeImageManifest,
			"artifactType":  artifactType,
			"config": map[string]any{
				"mediaType": modelspecv1.MediaTypeModelConfig,
				"digest":    configDescriptor.Digest.String(),
				"size":      configDescriptor.Size,
			},
			"layers": layerDescriptors,
		}),
	)

	return server.Reference(opts.repository, opts.tag)
}
