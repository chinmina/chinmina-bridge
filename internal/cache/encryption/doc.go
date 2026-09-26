// Package encryption loads and refreshes authenticated-encryption keysets for
// the distributed token cache. It constructs validated Tink AEAD primitives
// from KMS-encrypted keysets in AWS Secrets Manager or, for local development,
// cleartext keyset files.
//
// RefreshableAEAD owns background keyset refresh and exposes encryption and
// decryption through the active primitive. The cache package owns payload
// serialization and associated-data selection; this package owns key material
// and its lifecycle.
package encryption
