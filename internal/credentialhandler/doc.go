// Package credentialhandler reads and writes Git's line-oriented credential
// protocol and reconstructs repository URLs from credential properties.
// ArrayMap holds the property pairs; serialization validates them before
// writing so malformed properties do not produce a partially encoded response.
//
// Protocol and host are required to reconstruct a URL, but path is optional
// because Git may omit it when HTTP path matching is disabled. Reconstruction
// does not decide whether a destination is eligible for credentials: the bridge
// classifies request contexts and the vendor resolves repository scope.
package credentialhandler
