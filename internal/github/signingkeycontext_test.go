package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	appconfig "github.com/chinmina/chinmina-bridge/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Signing is lazy and recurring: a fresh App JWT roughly every ten minutes for
// the life of the process. If a signing key captures the context it was
// constructed under, the service boots cleanly, verifies cleanly, and then
// fails every mint with `context canceled` once that context ends —
// permanently, and with no configuration change to point at.
//
// The defect cannot reproduce with a PEM key: only a KMS-backed key makes a
// call that takes a context at all, and every other test in this package uses
// PEM. This test is the only thing standing between that regression and
// production, so it exercises signing directly rather than through a token
// source — an App JWT is cached for ten minutes once minted, so a test driving
// the cached path would pass whether or not the defect were present.
func TestKMSSigningKey_SignsAfterTheConstructionContextEnds(t *testing.T) {
	kms := setupMockKMS(t)
	setAWSTestEnvironment(t, kms.URL)

	constructionCtx, cancelConstruction := context.WithCancel(context.Background())

	key, err := createKMSSigningKey(
		"arn:aws:kms:ap-southeast-2:123456789012:key/test-key",
		newAWSConfigLoader(constructionCtx),
	)
	require.NoError(t, err)

	// Sign once while the construction context is live, so a key that captures
	// a context has certainly captured this one.
	_, err = kmsSigner{}.Sign(key, []byte("first-jwt"))
	require.NoError(t, err)

	// Startup is over. Everything scoped to it is now cancelled.
	cancelConstruction()

	_, err = kmsSigner{}.Sign(key, []byte("later-jwt"))

	require.NoError(t, err, "signing must not depend on the context the key was built under")
}

// The App JWT path is where the recurring signing actually happens, so it is
// asserted separately: a key that signs but a token source that cannot build a
// JWT from it is the same outage.
func TestKMSSigningKey_MintsAppJWTAfterTheConstructionContextEnds(t *testing.T) {
	kms := setupMockKMS(t)
	setAWSTestEnvironment(t, kms.URL)

	constructionCtx, cancelConstruction := context.WithCancel(context.Background())

	signingKey, err := createSigningKey(
		testGithubConfig("arn:aws:kms:ap-southeast-2:123456789012:key/test-key"),
		newAWSConfigLoader(constructionCtx),
	)
	require.NoError(t, err)

	cancelConstruction()

	// newAppTokenSource rather than NewAppTokenSource: the caching wrapper
	// would serve a JWT minted before cancellation and prove nothing.
	token, err := newAppTokenSource(signingKey, "333").Token()

	require.NoError(t, err, "App JWT minting must survive the end of the construction context")
	assert.NotEmpty(t, token.AccessToken)
}

// A PEM-backed key never touched a context, so it is the control: if this
// fails, the tests above are measuring something other than context capture.
func TestPEMSigningKey_IsUnaffectedByContextCancellation(t *testing.T) {
	constructionCtx, cancelConstruction := context.WithCancel(context.Background())

	cfg := testGithubConfig("")
	cfg.PrivateKey = generatePEMKey(t)

	signingKey, err := createSigningKey(cfg, newAWSConfigLoader(constructionCtx))
	require.NoError(t, err)

	cancelConstruction()

	token, err := newAppTokenSource(signingKey, "333").Token()

	require.NoError(t, err)
	assert.NotEmpty(t, token.AccessToken)
}

func testGithubConfig(arn string) appconfig.GithubConfig {
	return appconfig.GithubConfig{
		PrivateKeyARN:  arn,
		ApplicationID:  333,
		InstallationID: 444,
	}
}

// setupMockKMS answers KMS Sign with a well-formed but meaningless signature.
// Nothing verifies it: these tests are about whether the signing call can
// happen at all, not about what it produces.
func setupMockKMS(t *testing.T) *httptest.Server {
	t.Helper()

	signature := make([]byte, 256)
	_, err := rand.Read(signature)
	require.NoError(t, err)

	body := `{"KeyId":"test-key","Signature":"` +
		base64.StdEncoding.EncodeToString(signature) +
		`","SigningAlgorithm":"RSASSA_PKCS1_V1_5_SHA_256"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	return server
}

func setAWSTestEnvironment(t *testing.T, endpoint string) {
	t.Helper()

	t.Setenv("AWS_ENDPOINT_URL", endpoint)
	t.Setenv("AWS_REGION", "ap-southeast-2")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
}

func generatePEMKey(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}))
}
