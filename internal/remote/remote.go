package remote

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	orascontent "oras.land/oras-go/v2/content"
	orasregistry "oras.land/oras-go/v2/registry"
	orasremote "oras.land/oras-go/v2/registry/remote"
	orasauth "oras.land/oras-go/v2/registry/remote/auth"
	orascredentials "oras.land/oras-go/v2/registry/remote/credentials"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// ErrBlobNotFound indicates that the remote registry does not have the blob.
var ErrBlobNotFound = errors.New("blob not found")

// Options configures remote resolution and authentication.
type Options struct {
	PlainHTTP        bool
	DockerConfigPath string
	Username         string
	Password         string
	RegistryToken    string
	HTTPClient       *http.Client
}

// Artifact contains the root reference fetched from the registry.
type Artifact struct {
	ParsedReference orasregistry.Reference
	Repository      *orasremote.Repository
	RootDescriptor  ocispec.Descriptor
	RootBytes       []byte
}

// FetchReference resolves and fetches the root manifest addressed by ref.
func FetchReference(
	ctx context.Context,
	ref string,
	opts Options,
) (Artifact, error) {
	parsed, err := orasregistry.ParseReference(ref)
	if err != nil {
		return Artifact{}, fmt.Errorf("parse reference %q: %w", ref, err)
	}

	repo, err := orasremote.NewRepository(parsed.Registry + "/" + parsed.Repository)
	if err != nil {
		return Artifact{}, fmt.Errorf("create repository client: %w", err)
	}

	client, err := newAuthClient(opts)
	if err != nil {
		return Artifact{}, err
	}

	repo.Client = client
	repo.PlainHTTP = opts.PlainHTTP

	rootDescriptor, rootReader, err := repo.FetchReference(
		ctx,
		parsed.ReferenceOrDefault(),
	)
	if err != nil {
		return Artifact{}, fmt.Errorf("fetch reference %q: %w", ref, err)
	}
	defer func() { _ = rootReader.Close() }()

	rootBytes, err := orascontent.ReadAll(rootReader, rootDescriptor)
	if err != nil {
		return Artifact{}, fmt.Errorf("read root manifest: %w", err)
	}

	return Artifact{
		ParsedReference: parsed,
		Repository:      repo,
		RootDescriptor:  rootDescriptor,
		RootBytes:       rootBytes,
	}, nil
}

// FetchBlob fetches a blob by descriptor from the remote repository.
func FetchBlob(
	ctx context.Context,
	repo *orasremote.Repository,
	target ocispec.Descriptor,
) ([]byte, error) {
	exists, err := BlobExists(ctx, repo, target)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrBlobNotFound
	}

	blob, err := orascontent.FetchAll(ctx, repo.Blobs(), target)
	if err != nil {
		return nil, fmt.Errorf("fetch blob %s: %w", target.Digest, err)
	}

	return blob, nil
}

// BlobExists reports whether the blob exists in the remote repository.
func BlobExists(
	ctx context.Context,
	repo *orasremote.Repository,
	target ocispec.Descriptor,
) (bool, error) {
	exists, err := repo.Blobs().Exists(ctx, target)
	if err != nil {
		return false, fmt.Errorf("check blob %s: %w", target.Digest, err)
	}
	return exists, nil
}

func newAuthClient(opts Options) (*orasauth.Client, error) {
	client := *orasauth.DefaultClient
	if opts.HTTPClient != nil {
		client.Client = opts.HTTPClient
	}

	storeCredential, err := newStoreCredentialFunc(opts)
	if err != nil {
		return nil, err
	}

	explicit, hasExplicit := explicitCredential(opts)
	client.Credential = func(
		ctx context.Context,
		hostport string,
	) (orasauth.Credential, error) {
		if hasExplicit {
			return explicit, nil
		}
		if storeCredential != nil {
			return storeCredential(ctx, hostport)
		}
		return orasauth.EmptyCredential, nil
	}

	return &client, nil
}

func explicitCredential(opts Options) (orasauth.Credential, bool) {
	switch {
	case opts.RegistryToken != "":
		return orasauth.Credential{
			AccessToken: opts.RegistryToken,
		}, true
	case opts.Username != "":
		return orasauth.Credential{
			Username: opts.Username,
			Password: opts.Password,
		}, true
	default:
		return orasauth.Credential{}, false
	}
}

func newStoreCredentialFunc(
	opts Options,
) (orasauth.CredentialFunc, error) {
	configPath, explicit, err := dockerConfigPath(opts.DockerConfigPath)
	if err != nil {
		return nil, err
	}

	if configPath == "" {
		return nil, nil
	}

	if _, err := os.Stat(configPath); err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			return nil, nil
		}
		return nil, fmt.Errorf("stat docker config %q: %w", configPath, err)
	}

	store, err := orascredentials.NewStore(
		configPath,
		orascredentials.StoreOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("load docker credentials from %q: %w", configPath, err)
	}

	return orascredentials.Credential(store), nil
}

func dockerConfigPath(
	override string,
) (string, bool, error) {
	if override != "" {
		return override, true, nil
	}

	if dir := os.Getenv("DOCKER_CONFIG"); dir != "" {
		return filepath.Join(dir, "config.json"), false, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", false, fmt.Errorf("resolve home directory: %w", err)
	}

	return filepath.Join(homeDir, ".docker", "config.json"), false, nil
}
