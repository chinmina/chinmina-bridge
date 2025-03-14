# Testing Chinmina Bridge

You may need to test Chinmina in a variety of circumstances, such as:

- When you're developing new features
- When you're trialling Chinmina to see if it meets your needs

This document provides guidance on how to test Chinmina Bridge.

## Prerequisites

Before you start testing Chinmina Bridge, you need to have the following:

- A GitHub app installed in your Github organization, with the following details:
  - `GITHUB_APP_ID`
  - `GITHUB_APP_INSTALLATION_ID`
  - `GITHUB_APP_PRIVATE_KEY`
- A Buildkite pipeline with corresponding agent token
- A Buildkite API token

You'll then need to set the following environment variables to be fed into the `integration/docker-compose.yaml` file:


- GITHUB_APP_ID
- GITHUB_APP_INSTALLATION_ID
- BUILDKITE_API_TOKEN
- JWT_BUILDKITE_ORGANIZATION_SLUG
- BUILDKITE_AGENT_TOKEN
- BUILDKITE_AGENT_TAGS
- GITHUB_APP_PRIVATE_KEY

Once this is done, you can use the following command to compile your current code and start docker containers (including Jaeger for traces):

```bash
make docker
```

Jaeger will be available at `http://localhost:16686`.

## Running tests

From here you can interact with your locally deployed Chinmina instance by simply running pipelines that are associated with your agent token.

