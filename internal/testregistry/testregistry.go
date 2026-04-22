package testregistry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type blobRecord struct {
	Descriptor ocispec.Descriptor
	Content    []byte
}

type manifestRecord struct {
	Descriptor ocispec.Descriptor
	Content    []byte
}

type repository struct {
	blobs     map[digest.Digest]blobRecord
	manifests map[string]manifestRecord
}

// Server is a minimal registry server used for tests.
type Server struct {
	mu       sync.RWMutex
	server   *httptest.Server
	username string
	password string
	repos    map[string]*repository
}

// New creates a new in-memory registry server.
func New() *Server {
	s := &Server{
		repos: map[string]*repository{},
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// Close stops the server.
func (s *Server) Close() {
	s.server.Close()
}

// SetBasicAuth requires the given credentials for all registry requests.
func (s *Server) SetBasicAuth(username, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.username = username
	s.password = password
}

// Host returns the host:port of the test registry.
func (s *Server) Host() string {
	parsed, err := url.Parse(s.server.URL)
	if err != nil {
		panic(err)
	}
	return parsed.Host
}

// Reference returns a plain HTTP registry reference for the given repository.
func (s *Server) Reference(repository, reference string) string {
	return fmt.Sprintf("%s/%s:%s", s.Host(), repository, reference)
}

// AddBlob stores a blob in the given repository.
func (s *Server) AddBlob(
	repository string,
	mediaType string,
	content []byte,
) ocispec.Descriptor {
	s.mu.Lock()
	defer s.mu.Unlock()

	repo := s.ensureRepository(repository)
	descriptor := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(content),
		Size:      int64(len(content)),
	}
	repo.blobs[descriptor.Digest] = blobRecord{
		Descriptor: descriptor,
		Content:    append([]byte(nil), content...),
	}
	return descriptor
}

// DeleteBlob removes a blob from the repository.
func (s *Server) DeleteBlob(repository string, dgst digest.Digest) {
	s.mu.Lock()
	defer s.mu.Unlock()

	repo := s.ensureRepository(repository)
	delete(repo.blobs, dgst)
}

// AddManifest stores a manifest in the repository under the given reference.
func (s *Server) AddManifest(
	repository string,
	reference string,
	mediaType string,
	content []byte,
) ocispec.Descriptor {
	s.mu.Lock()
	defer s.mu.Unlock()

	repo := s.ensureRepository(repository)
	descriptor := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(content),
		Size:      int64(len(content)),
	}
	record := manifestRecord{
		Descriptor: descriptor,
		Content:    append([]byte(nil), content...),
	}
	repo.manifests[reference] = record
	repo.manifests[descriptor.Digest.String()] = record
	return descriptor
}

func (s *Server) ensureRepository(name string) *repository {
	repo, ok := s.repos[name]
	if !ok {
		repo = &repository{
			blobs:     map[digest.Digest]blobRecord{},
			manifests: map[string]manifestRecord{},
		}
		s.repos[name] = repo
	}
	return repo
}

func (s *Server) handle(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !s.authorized(w, r) {
		return
	}

	if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
		w.WriteHeader(http.StatusOK)
		return
	}

	const prefix = "/v2/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, prefix)
	switch {
	case strings.Contains(path, "/manifests/"):
		repository, reference, ok := strings.Cut(path, "/manifests/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		s.serveManifest(w, r, repository, reference)
	case strings.Contains(path, "/blobs/"):
		repository, dgst, ok := strings.Cut(path, "/blobs/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		s.serveBlob(w, r, repository, dgst)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) authorized(
	w http.ResponseWriter,
	r *http.Request,
) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.username == "" {
		return true
	}

	username, password, ok := r.BasicAuth()
	if ok && username == s.username && password == s.password {
		return true
	}

	w.Header().Set("WWW-Authenticate", `Basic realm="testregistry"`)
	w.WriteHeader(http.StatusUnauthorized)
	return false
}

func (s *Server) serveManifest(
	w http.ResponseWriter,
	r *http.Request,
	repository string,
	reference string,
) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	repo, ok := s.repos[repository]
	if !ok {
		http.NotFound(w, r)
		return
	}

	record, ok := repo.manifests[reference]
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", record.Descriptor.MediaType)
	w.Header().Set("Docker-Content-Digest", record.Descriptor.Digest.String())
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(record.Content)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(record.Content)
}

func (s *Server) serveBlob(
	w http.ResponseWriter,
	r *http.Request,
	repository string,
	rawDigest string,
) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	repo, ok := s.repos[repository]
	if !ok {
		http.NotFound(w, r)
		return
	}

	dgst, err := digest.Parse(rawDigest)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	record, ok := repo.blobs[dgst]
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", record.Descriptor.Digest.String())
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(record.Content)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(record.Content)
}

// JSON marshals v or panics in tests.
func JSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
