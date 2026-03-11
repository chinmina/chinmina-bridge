package vendor

import (
	"crypto/sha256"
	"encoding/base64"
)

// HashToken computes the SHA-256 hash of token and returns it base64-encoded.
// This matches the format used by GitHub's audit log for correlating token usage:
// https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/identifying-audit-log-events-performed-by-an-access-token
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(hash[:])
}
