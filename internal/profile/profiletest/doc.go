// Package profiletest builds compiled profiles and profile stores for tests
// outside the profile package. It supplies YAML through a mock content source
// while exercising the production retrieval and compilation entry point.
//
// Tests can provide an app lookup to model named GitHub Apps; without one,
// only the default app is usable. Embedded profiles provide shared test data
// without making callers depend on profile's unexported implementation.
package profiletest
