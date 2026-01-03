package buildkite_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	api "github.com/buildkite/go-buildkite/v4"
	"github.com/chinmina/chinmina-bridge/internal/buildkite"
	"github.com/chinmina/chinmina-bridge/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigFails(t *testing.T) {
	t.Run("NoToken", func(t *testing.T) {
		_, err := buildkite.New(config.BuildkiteConfig{
			Token:  "",
			APIURL: "",
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "token must be configured for Buildkite API access")
	})

	t.Run("InvalidURL", func(t *testing.T) {
		_, err := buildkite.New(config.BuildkiteConfig{
			Token:  "asdbv",
			APIURL: "://",
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "could not parse Buildkite API URL")
	})
}

func TestRepositoryLookup_Succeeds(t *testing.T) {
	router := http.NewServeMux()

	router.HandleFunc("/v2/organizations/{organization}/pipelines/{pipeline}", func(w http.ResponseWriter, r *http.Request) {
		org := r.PathValue("organization")
		pipeline := r.PathValue("pipeline")

		w.Header().Set("Content-Type", "application/json")
		pl := &api.Pipeline{
			Name:        pipeline,
			Slug:        pipeline,
			Repository:  "urn:expected-repository-url",
			Description: org,
			Tags: []string{
				"token:" + r.Header.Get("Authorization"),
			},
		}
		res, _ := json.Marshal(&pl)
		_, _ = w.Write(res)
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	bk, err := buildkite.New(config.BuildkiteConfig{
		Token:  "expected-token",
		APIURL: svr.URL,
	})
	require.NoError(t, err)

	repo, err := bk.RepositoryLookup(context.Background(), "expected-organization", "expected-pipeline")

	require.NoError(t, err)
	assert.Equal(t, "urn:expected-repository-url", repo)
}

func TestRepositoryLookup_SendsAuthToken(t *testing.T) {
	router := http.NewServeMux()

	var actualToken string

	router.HandleFunc("/v2/organizations/{organization}/pipelines/{pipeline}", func(w http.ResponseWriter, r *http.Request) {
		org := r.PathValue("organization")
		pipeline := r.PathValue("pipeline")

		// capture the token to assert against
		actualToken = r.Header.Get("Authorization")

		w.Header().Set("Content-Type", "application/json")
		pl := &api.Pipeline{
			Name:        pipeline,
			Slug:        pipeline,
			Repository:  "urn:expected-repository-url",
			Description: org,
			Tags: []string{
				"token:" + r.Header.Get("Authorization"),
			},
		}
		res, _ := json.Marshal(&pl)
		_, _ = w.Write(res)
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	bk, err := buildkite.New(config.BuildkiteConfig{
		Token:  "expected-token",
		APIURL: svr.URL,
	})
	require.NoError(t, err)

	_, err = bk.RepositoryLookup(context.Background(), "expected-organization", "expected-pipeline")

	require.NoError(t, err)
	assert.Equal(t, "Bearer expected-token", actualToken)
}

func TestRepositoryLookup_FailsWhenRepoNotConfigured(t *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("/v2/organizations/{organization}/pipelines/{pipeline}", func(w http.ResponseWriter, r *http.Request) {
		org := r.PathValue("organization")
		pipeline := r.PathValue("pipeline")
		w.Header().Set("Content-Type", "application/json")
		pl := &api.Pipeline{
			Name: pipeline,
			Slug: pipeline,
			//Repository: // repository purposefully blank
			Description: org,
		}
		res, _ := json.Marshal(&pl)
		_, _ = w.Write(res)
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	bk, err := buildkite.New(config.BuildkiteConfig{
		Token:  "expected-token",
		APIURL: svr.URL,
	})
	require.NoError(t, err)

	_, err = bk.RepositoryLookup(context.Background(), "expected-organization", "expected-pipeline")

	require.Error(t, err)
	assert.ErrorContains(t, err, "no configured repository for pipeline expected-organization/expected-pipeline")
}

func TestRepositoryLookup_Fails(t *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("/v2/organizations/{organization}/pipelines/{pipeline}", func(w http.ResponseWriter, r *http.Request) {
		// teapot is useful for test
		w.WriteHeader(http.StatusTeapot)
	})

	svr := httptest.NewServer(router)
	defer svr.Close()

	bk, err := buildkite.New(config.BuildkiteConfig{
		Token:  "expected-token",
		APIURL: svr.URL,
	})
	require.NoError(t, err)

	_, err = bk.RepositoryLookup(context.Background(), "expected-organization", "expected-pipeline")

	require.Error(t, err)
	assert.ErrorContains(t, err, ": 418")
}
