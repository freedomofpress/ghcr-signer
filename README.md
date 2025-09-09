# GHCR Signature Publisher

Publish container signatures to the Github Container Registry (ghcr.io) when Github Personal Access Tokens (PATs) are disabled.

*Disabling PATs is considered a good security practice: these tokens aren't fine-grained and as such can give more privileges than intended to the bearer. Unfortunately, the Github Container Registry doesn't provide any other mechanism of authentication*

Traditionally, container signatures are generated and published in one step using
`cosign --sign`, but in situations where Github PAT tokens are disabled, this is unpractical.

## Usage

The flow is as follows:

1. Prepare the signatures using the `ghcr-signer.py` script
2. Create a pull request, with the signatures
3. The CI verifies the signatures are valid
4. A workflow is triggered when the signatures are published to the `main` branch.

### Preparing the signatures

Generate a signature and certificate locally, without publishing them:

```sh
export IMAGE="ghcr.io/freedomofpress/dangerzone/dangerzone@sha256:<hash>"
uv run ./ghcr-signer.py prepare "$IMAGE"
```

### Publishing Signatures

When the `main` branch is pushed, a workflow will:

- Detect which hashes haven't been published yet
- Attach signatures to the container registry using Github credentials
