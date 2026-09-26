# Bridge changes

- Use the error helpers in `handlers.go` (`requestError`, `writeJSONError`, or `writeTextError`) so failures retain audit recording and the endpoint's response format.
- Extend `APITestHarness` in `harness_integration_test.go` for end-to-end handler tests with mocked upstream services instead of creating another harness.
