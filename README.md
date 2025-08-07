# GHCR Signature Publisher

Publish signatures on ghcr.io when Github PAT (Personal Access Tokens) tokens are disabled.

Traditionally, signatures are generated and published in one step using
`cosign --sign` but in situations where Github PAT tokens are disabled (for
security reasons), this is unpractical.

## Usage

### Preparing Signatures

```sh
export IMAGE="ghcr.io/freedomofpress/dangerzone/dangerzone@sha256:<hash>"
uv run ./ghcr-signature.py prepare --image "$IMAGE"
```

When receiving this command, the script will:

- Extract the hash
- Generate a payload using `cosign generate`
- Generate a signature and certificate locally, without publishing them
- Commit the generated signature and certificate files to a local directory under the image hash

### Publishing Signatures

When the `main` branch is pushed, a workflow will:

- Detect which hashes haven't been published yet
- Attach signatures to the container registry using Github credentials
- Move processed signatures to an `UPLOADED` directory

## Workflow

The GitHub Actions workflow automatically runs the `publish` command to:

- Attach signatures to their respective images
- Move processed signatures to the `UPLOADED` directory

