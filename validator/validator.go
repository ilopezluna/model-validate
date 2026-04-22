package validator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	modelschema "github.com/modelpack/model-spec/schema"
	modelspecv1 "github.com/modelpack/model-spec/specs-go/v1"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	remoteaccess "github.com/ilopezluna/model-validate/internal/remote"
)

const (
	specRefManifest    = "docs/spec.md#oci-image-manifest-specification-for-model-artifacts"
	specRefConfig      = "docs/config.md#properties"
	specRefAnnotations = "docs/annotations.md#pre-defined-annotation-keys"
)

type requirement uint8

const (
	requirementMust requirement = iota + 1
	requirementShould
)

type collector struct {
	policy   Policy
	findings []Finding
}

type unknownDocument struct {
	MediaType     string          `json:"mediaType,omitempty"`
	Config        json.RawMessage `json:"config,omitempty"`
	Layers        json.RawMessage `json:"layers,omitempty"`
	Manifests     json.RawMessage `json:"manifests,omitempty"`
	FSLayers      json.RawMessage `json:"fsLayers,omitempty"`
	SchemaVersion int             `json:"schemaVersion,omitempty"`
}

type rawDescriptor struct {
	MediaType   string            `json:"mediaType,omitempty"`
	Digest      string            `json:"digest,omitempty"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type rawManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType,omitempty"`
	ArtifactType  string          `json:"artifactType,omitempty"`
	Config        rawDescriptor   `json:"config"`
	Layers        []rawDescriptor `json:"layers"`
}

type rawModel struct {
	ModelFS rawModelFS `json:"modelfs"`
}

type rawModelFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diffIds"`
}

type fileMetadata struct {
	Name     string    `json:"name"`
	Mode     uint32    `json:"mode"`
	UID      uint32    `json:"uid"`
	GID      uint32    `json:"gid"`
	Size     int64     `json:"size"`
	ModTime  time.Time `json:"mtime"`
	Typeflag byte      `json:"typeflag"`
}

// ValidateReference validates a remote OCI reference against the ModelPack spec.
func ValidateReference(
	ctx context.Context,
	ref string,
	opts Options,
) (Result, error) {
	result := Result{
		Reference: ref,
		Policy:    normalizePolicy(opts.Policy),
	}

	if err := validateOptions(opts); err != nil {
		return result, err
	}

	artifact, err := remoteaccess.FetchReference(
		ctx,
		ref,
		remoteaccess.Options{
			PlainHTTP:        opts.PlainHTTP,
			DockerConfigPath: opts.DockerConfigPath,
			Username:         opts.Username,
			Password:         opts.Password,
			RegistryToken:    opts.RegistryToken,
			HTTPClient:       opts.HTTPClient,
		},
	)
	if err != nil {
		return result, err
	}

	result.ResolvedDigest = artifact.RootDescriptor.Digest.String()

	issues := collector{policy: result.Policy}
	issues.validateRootDescriptor(artifact.RootDescriptor)

	doc, rawManifest, ok := issues.inspectRootDocument(
		artifact.RootDescriptor,
		artifact.RootBytes,
	)
	if !ok {
		result.finalize(issues.findings)
		return result, nil
	}

	if doc.MediaType != "" &&
		doc.MediaType != ocispec.MediaTypeImageManifest {
		issues.add(requirementMust, Finding{
			Code: "root-not-manifest",
			Message: fmt.Sprintf(
				"root document mediaType %q is not an OCI image manifest",
				doc.MediaType,
			),
			Path:             "manifest.mediaType",
			DescriptorDigest: artifact.RootDescriptor.Digest.String(),
			SpecRef:          specRefManifest,
		})
	}

	issues.validateManifest(
		artifact.RootDescriptor,
		artifact.RootBytes,
		rawManifest,
	)

	configDescriptor, haveConfig := issues.toDescriptor(
		rawManifest.Config,
		"manifest.config",
		"invalid-config-descriptor",
		specRefManifest,
	)
	if haveConfig {
		configBytes, err := remoteaccess.FetchBlob(
			ctx,
			artifact.Repository,
			configDescriptor,
		)
		if err != nil {
			if errors.Is(err, remoteaccess.ErrBlobNotFound) {
				issues.add(requirementMust, Finding{
					Code:             "missing-blob",
					Message:          "config blob is missing from the registry",
					Path:             "manifest.config",
					DescriptorDigest: configDescriptor.Digest.String(),
					SpecRef:          specRefManifest,
				})
			} else {
				return result, err
			}
		} else {
			issues.validateConfig(configDescriptor, configBytes, len(rawManifest.Layers))
		}
	}

	for index, layer := range rawManifest.Layers {
		path := fmt.Sprintf("manifest.layers[%d]", index)
		layerDescriptor, ok := issues.toDescriptor(
			layer,
			path,
			"invalid-layer-descriptor",
			specRefManifest,
		)
		if !ok {
			continue
		}

		if layer.MediaType == "" {
			issues.add(requirementMust, Finding{
				Code:             "invalid-layer-descriptor",
				Message:          "layer mediaType must not be empty",
				Path:             path + ".mediaType",
				DescriptorDigest: layerDescriptor.Digest.String(),
				SpecRef:          specRefManifest,
			})
		} else if !isKnownLayerMediaType(layer.MediaType) {
			issues.add(requirementShould, Finding{
				Code:             "unknown-layer-media-type",
				Message:          fmt.Sprintf("layer mediaType %q is not defined by model-spec", layer.MediaType),
				Path:             path + ".mediaType",
				DescriptorDigest: layerDescriptor.Digest.String(),
				SpecRef:          specRefManifest,
			})
		}

		if err := issues.validateAnnotations(path, layerDescriptor); err != nil {
			return result, err
		}

		exists, err := remoteaccess.BlobExists(ctx, artifact.Repository, layerDescriptor)
		if err != nil {
			return result, err
		}
		if !exists {
			issues.add(requirementMust, Finding{
				Code:             "missing-blob",
				Message:          "layer blob is missing from the registry",
				Path:             path,
				DescriptorDigest: layerDescriptor.Digest.String(),
				SpecRef:          specRefManifest,
			})
		}
	}

	result.finalize(issues.findings)
	return result, nil
}

func normalizePolicy(policy Policy) Policy {
	switch policy {
	case PolicyStrict, PolicyMustOnly:
		return policy
	default:
		return PolicyDefault
	}
}

func validateOptions(opts Options) error {
	if opts.RegistryToken != "" && opts.Username != "" {
		return errors.New("registry token cannot be combined with username/password")
	}
	if opts.RegistryToken != "" && opts.Password != "" {
		return errors.New("registry token cannot be combined with username/password")
	}
	if opts.Username == "" && opts.Password != "" {
		return errors.New("password requires a username")
	}
	return nil
}

func (c *collector) inspectRootDocument(
	root ocispec.Descriptor,
	body []byte,
) (unknownDocument, rawManifest, bool) {
	var doc unknownDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		c.add(requirementMust, Finding{
			Code:             "invalid-manifest-json",
			Message:          fmt.Sprintf("root manifest is not valid JSON: %v", err),
			Path:             "manifest",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
		return unknownDocument{}, rawManifest{}, false
	}

	if len(doc.FSLayers) != 0 {
		c.add(requirementMust, Finding{
			Code:             "schema1-not-supported",
			Message:          "Docker schema 1 manifests are not supported",
			Path:             "manifest.fsLayers",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
		return doc, rawManifest{}, false
	}

	if root.MediaType == ocispec.MediaTypeImageIndex ||
		len(doc.Manifests) != 0 ||
		doc.MediaType == ocispec.MediaTypeImageIndex {
		c.add(requirementMust, Finding{
			Code:             "root-not-manifest",
			Message:          "root descriptor resolves to an OCI index, not an OCI image manifest",
			Path:             "manifest",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
		return doc, rawManifest{}, false
	}

	var manifest rawManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		c.add(requirementMust, Finding{
			Code:             "invalid-manifest-json",
			Message:          fmt.Sprintf("root manifest could not be decoded: %v", err),
			Path:             "manifest",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
		return doc, rawManifest{}, false
	}

	return doc, manifest, true
}

func (c *collector) validateRootDescriptor(root ocispec.Descriptor) {
	if root.Size < 0 {
		c.add(requirementMust, Finding{
			Code:             "invalid-root-descriptor",
			Message:          "root descriptor size must be >= 0",
			Path:             "manifest",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
	}
	if err := root.Digest.Validate(); err != nil {
		c.add(requirementMust, Finding{
			Code:             "invalid-root-descriptor",
			Message:          fmt.Sprintf("root descriptor digest is invalid: %v", err),
			Path:             "manifest",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
	}
}

func (c *collector) validateManifest(
	root ocispec.Descriptor,
	body []byte,
	manifest rawManifest,
) {
	if manifest.SchemaVersion != 2 {
		c.add(requirementMust, Finding{
			Code:             "invalid-schema-version",
			Message:          fmt.Sprintf("schemaVersion must be 2, got %d", manifest.SchemaVersion),
			Path:             "manifest.schemaVersion",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
	}

	if manifest.MediaType != ocispec.MediaTypeImageManifest {
		c.add(requirementMust, Finding{
			Code:             "invalid-manifest-media-type",
			Message:          fmt.Sprintf("manifest mediaType must be %q", ocispec.MediaTypeImageManifest),
			Path:             "manifest.mediaType",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
	}

	if root.MediaType != "" &&
		manifest.MediaType != "" &&
		root.MediaType != manifest.MediaType {
		c.add(requirementMust, Finding{
			Code:             "media-type-mismatch",
			Message:          fmt.Sprintf("descriptor mediaType %q does not match document mediaType %q", root.MediaType, manifest.MediaType),
			Path:             "manifest.mediaType",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
	}

	if manifest.ArtifactType != modelspecv1.ArtifactTypeModelManifest {
		c.add(requirementMust, Finding{
			Code:             "invalid-artifact-type",
			Message:          fmt.Sprintf("artifactType must be %q", modelspecv1.ArtifactTypeModelManifest),
			Path:             "manifest.artifactType",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
	}

	if len(manifest.Layers) == 0 {
		c.add(requirementMust, Finding{
			Code:             "missing-layers",
			Message:          "manifest.layers must contain at least one layer",
			Path:             "manifest.layers",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
	}

	if bytes.Count(body, []byte(`"manifests"`)) != 0 {
		c.add(requirementMust, Finding{
			Code:             "media-type-mismatch",
			Message:          "manifest payload contains index-style fields",
			Path:             "manifest",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
	}

	if manifest.Config.MediaType != modelspecv1.MediaTypeModelConfig {
		c.add(requirementMust, Finding{
			Code:             "invalid-config-descriptor",
			Message:          fmt.Sprintf("config mediaType must be %q", modelspecv1.MediaTypeModelConfig),
			Path:             "manifest.config.mediaType",
			DescriptorDigest: root.Digest.String(),
			SpecRef:          specRefManifest,
		})
	}
}

func (c *collector) validateConfig(
	configDescriptor ocispec.Descriptor,
	body []byte,
	layerCount int,
) {
	if err := modelschema.Validator(
		modelschema.ValidatorMediaTypeModelConfig,
	).Validate(bytes.NewReader(body)); err != nil {
		c.add(requirementMust, Finding{
			Code:             "invalid-model-config",
			Message:          err.Error(),
			Path:             "config",
			DescriptorDigest: configDescriptor.Digest.String(),
			SpecRef:          specRefConfig,
		})
		return
	}

	var model rawModel
	if err := json.Unmarshal(body, &model); err != nil {
		c.add(requirementMust, Finding{
			Code:             "invalid-model-config",
			Message:          fmt.Sprintf("config JSON could not be decoded: %v", err),
			Path:             "config",
			DescriptorDigest: configDescriptor.Digest.String(),
			SpecRef:          specRefConfig,
		})
		return
	}

	if model.ModelFS.Type != "layers" {
		c.add(requirementMust, Finding{
			Code:             "invalid-modelfs-type",
			Message:          `modelfs.type must be "layers"`,
			Path:             "config.modelfs.type",
			DescriptorDigest: configDescriptor.Digest.String(),
			SpecRef:          specRefConfig,
		})
	}

	if len(model.ModelFS.DiffIDs) != layerCount {
		c.add(requirementMust, Finding{
			Code:             "diffid-count-mismatch",
			Message:          fmt.Sprintf("config.modelfs.diffIds has %d items but manifest.layers has %d", len(model.ModelFS.DiffIDs), layerCount),
			Path:             "config.modelfs.diffIds",
			DescriptorDigest: configDescriptor.Digest.String(),
			SpecRef:          specRefConfig,
		})
	}

	for index, diffID := range model.ModelFS.DiffIDs {
		if _, err := digest.Parse(diffID); err != nil {
			c.add(requirementMust, Finding{
				Code:             "invalid-diffid",
				Message:          fmt.Sprintf("diffId is not a valid digest: %v", err),
				Path:             fmt.Sprintf("config.modelfs.diffIds[%d]", index),
				DescriptorDigest: configDescriptor.Digest.String(),
				SpecRef:          specRefConfig,
			})
		}
	}
}

func (c *collector) validateAnnotations(
	path string,
	layer ocispec.Descriptor,
) error {
	if len(layer.Annotations) == 0 {
		return nil
	}

	const (
		annotationFilepath          = "org.cncf.model.filepath"
		annotationFileMetadata      = "org.cncf.model.file.metadata+json"
		annotationMediaTypeUntested = "org.cncf.model.file.mediatype.untested"
	)

	if value, ok := layer.Annotations[annotationFilepath]; ok && value == "" {
		c.add(requirementMust, Finding{
			Code:             "invalid-annotation",
			Message:          "org.cncf.model.filepath must not be empty",
			Path:             path + `.annotations["` + annotationFilepath + `"]`,
			DescriptorDigest: layer.Digest.String(),
			SpecRef:          specRefAnnotations,
		})
	}

	if value, ok := layer.Annotations[annotationMediaTypeUntested]; ok {
		if value != "true" && value != "false" {
			c.add(requirementMust, Finding{
				Code:             "invalid-annotation",
				Message:          `org.cncf.model.file.mediatype.untested must be "true" or "false"`,
				Path:             path + `.annotations["` + annotationMediaTypeUntested + `"]`,
				DescriptorDigest: layer.Digest.String(),
				SpecRef:          specRefAnnotations,
			})
		}
	}

	if value, ok := layer.Annotations[annotationFileMetadata]; ok {
		var metadata fileMetadata
		if err := json.Unmarshal([]byte(value), &metadata); err != nil {
			c.add(requirementMust, Finding{
				Code:             "invalid-annotation",
				Message:          fmt.Sprintf("org.cncf.model.file.metadata+json is not valid JSON: %v", err),
				Path:             path + `.annotations["` + annotationFileMetadata + `"]`,
				DescriptorDigest: layer.Digest.String(),
				SpecRef:          specRefAnnotations,
			})
		}
	}

	return nil
}

func (c *collector) toDescriptor(
	raw rawDescriptor,
	path string,
	code string,
	specRef string,
) (ocispec.Descriptor, bool) {
	if raw.Size < 0 {
		c.add(requirementMust, Finding{
			Code:    code,
			Message: "descriptor size must be >= 0",
			Path:    path + ".size",
			SpecRef: specRef,
		})
		return ocispec.Descriptor{}, false
	}

	dgst, err := digest.Parse(raw.Digest)
	if err != nil {
		c.add(requirementMust, Finding{
			Code:    code,
			Message: fmt.Sprintf("descriptor digest is invalid: %v", err),
			Path:    path + ".digest",
			SpecRef: specRef,
		})
		return ocispec.Descriptor{}, false
	}

	return ocispec.Descriptor{
		MediaType:   raw.MediaType,
		Digest:      dgst,
		Size:        raw.Size,
		Annotations: raw.Annotations,
	}, true
}

func (c *collector) add(req requirement, finding Finding) {
	switch req {
	case requirementMust:
		finding.Severity = SeverityError
	case requirementShould:
		switch c.policy {
		case PolicyMustOnly:
			return
		case PolicyStrict:
			finding.Severity = SeverityError
		default:
			finding.Severity = SeverityWarning
		}
	}

	c.findings = append(c.findings, finding)
}

func (r *Result) finalize(findings []Finding) {
	r.Findings = findings
	for _, finding := range findings {
		switch finding.Severity {
		case SeverityError:
			r.ErrorCount++
		case SeverityWarning:
			r.WarningCount++
		}
	}
	r.Compliant = r.ErrorCount == 0
}

func isKnownLayerMediaType(mediaType string) bool {
	switch mediaType {
	case modelspecv1.MediaTypeModelWeightRaw,
		modelspecv1.MediaTypeModelWeight,
		modelspecv1.MediaTypeModelWeightGzip,
		modelspecv1.MediaTypeModelWeightZstd,
		modelspecv1.MediaTypeModelWeightConfigRaw,
		modelspecv1.MediaTypeModelWeightConfig,
		modelspecv1.MediaTypeModelWeightConfigGzip,
		modelspecv1.MediaTypeModelWeightConfigZstd,
		modelspecv1.MediaTypeModelDocRaw,
		modelspecv1.MediaTypeModelDoc,
		modelspecv1.MediaTypeModelDocGzip,
		modelspecv1.MediaTypeModelDocZstd,
		modelspecv1.MediaTypeModelCodeRaw,
		modelspecv1.MediaTypeModelCode,
		modelspecv1.MediaTypeModelCodeGzip,
		modelspecv1.MediaTypeModelCodeZstd,
		modelspecv1.MediaTypeModelDatasetRaw,
		modelspecv1.MediaTypeModelDataset,
		modelspecv1.MediaTypeModelDatasetGzip,
		modelspecv1.MediaTypeModelDatasetZstd:
		return true
	default:
		return false
	}
}
