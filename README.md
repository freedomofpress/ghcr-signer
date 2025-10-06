# GHCR Signature Publisher

This repository allows to publish container signatures to the Github Container Registry (ghcr.io) when Github Personal Access Tokens (PATs) are disabled.

_Disabling PATs is considered a good security practice: these tokens aren't fine-grained and as such can give more privileges than intended to the bearer. Unfortunately, the Github Container Registry [doesn't provide](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-to-the-container-registry) any other mechanism of authentication._

Traditionally, container signatures are generated and published in one step using
`cosign --sign`, but in situations where Github PAT tokens are disabled, this is impractical.

## Usage

The flow is as follows:

1. Prepare the signatures locally
2. Create a pull request, with the signatures
3. The CI ensures signatures are valid
4. The pull request is merged in the `main` branch
5. A workflow is triggered, publishing the signatures to the registry.

### Preparing the signatures

Generate signatures locally, without publishing it. Make sure to pass the image
name and its hash, without labels:

```sh
export IMAGE="ghcr.io/freedomofpress/dangerzone/dangerzone@sha256:<hash>"
uv run ./ghcr-signer.py prepare --recursive "$IMAGE"
```

_You should pass a key via `--key` or `--sk` (in case of a hardware key)._

### Publishing Signatures

When the `main` branch is updated with new content inside the `SIGNATURES` folder,
a workflow will:

- Detect the latest folder, based on its date
- Attach signatures to the container registry using Github credentials
