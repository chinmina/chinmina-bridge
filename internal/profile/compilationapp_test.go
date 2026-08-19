package profile

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// usableApps builds a lookup over a fixed set of enabled app names, plus the
// default. The registry answers no for an unknown app and a disabled one alike.
func usableApps(names ...string) AppLookup {
	usable := map[string]struct{}{"default": {}}
	for _, name := range names {
		usable[name] = struct{}{}
	}

	return func(name string) bool {
		_, found := usable[name]
		return found
	}
}

func compileYAML(t *testing.T, yamlContent string, usableApp AppLookup) Profiles {
	t.Helper()

	config, digest, err := parse(yamlContent)
	require.NoError(t, err)

	profiles, err := compile(config, digest, "local", usableApp)
	require.NoError(t, err)

	return profiles
}

// An omitted app and an explicit `app: default` must be indistinguishable
// downstream, so compilation normalises rather than the request boundary.
func TestCompile_AppNormalization(t *testing.T) {
	tests := []struct {
		name     string
		app      string
		expected string
	}{
		{name: "omitted resolves to the default app", app: "", expected: "default"},
		{name: "explicit default is accepted", app: "\n      app: default", expected: "default"},
		{name: "an enabled registry app is accepted", app: "\n      app: packages", expected: "packages"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profiles := compileYAML(t, `
organization:
  profiles:
    - name: publish`+tt.app+`
      repositories: ["silk"]
      permissions: ["contents:read"]
pipeline:
  profiles:
    - name: build`+tt.app+`
      permissions: ["contents:read"]
`, usableApps("packages"))

			org, err := profiles.GetOrgProfile("publish")
			require.NoError(t, err)
			assert.Equal(t, tt.expected, org.Attrs.App)

			pipeline, err := profiles.GetPipelineProfile("build")
			require.NoError(t, err)
			assert.Equal(t, tt.expected, pipeline.Attrs.App)
		})
	}
}

// Equality is asserted over the whole attribute set, not just the app name:
// any remaining difference is something a downstream stage can act on.
func TestCompile_OmittedAndExplicitDefaultProduceEqualAttributes(t *testing.T) {
	omitted := compileYAML(t, `
organization:
  profiles:
    - name: publish
      repositories: ["silk"]
      permissions: ["contents:read"]
pipeline:
  profiles:
    - name: build
      permissions: ["contents:read"]
`, DefaultAppOnly)

	explicit := compileYAML(t, `
organization:
  profiles:
    - name: publish
      app: default
      repositories: ["silk"]
      permissions: ["contents:read"]
pipeline:
  profiles:
    - name: build
      app: default
      permissions: ["contents:read"]
`, DefaultAppOnly)

	omittedOrg, err := omitted.GetOrgProfile("publish")
	require.NoError(t, err)
	explicitOrg, err := explicit.GetOrgProfile("publish")
	require.NoError(t, err)
	assert.Equal(t, omittedOrg.Attrs, explicitOrg.Attrs)

	omittedPipeline, err := omitted.GetPipelineProfile("build")
	require.NoError(t, err)
	explicitPipeline, err := explicit.GetPipelineProfile("build")
	require.NoError(t, err)
	assert.Equal(t, omittedPipeline.Attrs, explicitPipeline.Attrs)
}

// A profile naming an unusable app is invalid, and only that profile is: one
// operator error must not withdraw every other profile in the configuration.
func TestCompile_RejectsUnusableApp(t *testing.T) {
	tests := []struct {
		name        string
		app         string
		expectedErr string
	}{
		{
			name:        "empty app names nothing",
			app:         `app: ""`,
			expectedErr: "app must not be empty",
		},
		{
			name:        "unknown app is not in the registry",
			app:         `app: nonexistent`,
			expectedErr: `app "nonexistent" is not a configured, enabled application`,
		},
		{
			name:        "disabled app is not resolvable",
			app:         `app: disabled-packages`,
			expectedErr: `app "disabled-packages" is not a configured, enabled application`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profiles := compileYAML(t, `
organization:
  profiles:
    - name: broken
      `+tt.app+`
      repositories: ["silk"]
      permissions: ["contents:read"]
    - name: healthy
      app: packages
      repositories: ["cotton"]
      permissions: ["contents:read"]
pipeline:
  profiles:
    - name: broken-pipeline
      `+tt.app+`
      permissions: ["contents:read"]
    - name: healthy-pipeline
      permissions: ["contents:read"]
`, usableApps("packages"))

			_, err := profiles.GetOrgProfile("broken")
			var unavailable ProfileUnavailableError
			require.ErrorAs(t, err, &unavailable)
			assert.ErrorContains(t, err, tt.expectedErr)

			_, err = profiles.GetPipelineProfile("broken-pipeline")
			require.ErrorAs(t, err, &unavailable)
			assert.ErrorContains(t, err, tt.expectedErr)

			healthy, err := profiles.GetOrgProfile("healthy")
			require.NoError(t, err)
			assert.Equal(t, "packages", healthy.Attrs.App)

			healthyPipeline, err := profiles.GetPipelineProfile("healthy-pipeline")
			require.NoError(t, err)
			assert.Equal(t, "default", healthyPipeline.Attrs.App)
		})
	}
}

// The default pipeline profile is synthesised, so it has no YAML to carry an
// app property and always mints through the default app.
func TestCompile_DefaultPipelineProfileUsesTheDefaultApp(t *testing.T) {
	profiles := compileYAML(t, `
pipeline:
  defaults:
    permissions: ["contents:read"]
  profiles:
    - name: build
      app: packages
      permissions: ["packages:write"]
`, usableApps("packages"))

	defaultProfile, err := profiles.GetPipelineProfile("default")
	require.NoError(t, err)
	assert.Equal(t, "default", defaultProfile.Attrs.App)

	// The reserved name prevents the YAML redefining it with an app.
	reserved := compileYAML(t, `
pipeline:
  profiles:
    - name: default
      app: packages
      permissions: ["packages:write"]
`, usableApps("packages"))

	stillDefault, err := reserved.GetPipelineProfile("default")
	require.NoError(t, err)
	assert.Equal(t, "default", stillDefault.Attrs.App)
	assert.Equal(t, []string{"contents:read", "metadata:read"}, stillDefault.Attrs.Permissions)
}

func TestCompile_DefaultAppIsUsableWithoutARegistry(t *testing.T) {
	profiles := compileYAML(t, `
organization:
  profiles:
    - name: publish
      app: default
      repositories: ["silk"]
      permissions: ["contents:read"]
`, DefaultAppOnly)

	org, err := profiles.GetOrgProfile("publish")
	require.NoError(t, err)
	assert.Equal(t, "default", org.Attrs.App)
}
