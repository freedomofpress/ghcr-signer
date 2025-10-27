# /// script
# dependencies = [
#     "click",
# ]
# ///

import datetime
import json
import os
import shlex
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import click

HERE = Path(__file__).parent
ASSETS = HERE / Path("assets")
COSIGN = ASSETS / "cosign"
ORAS = ASSETS / "oras" / "oras"
CRANE = ASSETS / "crane" / "crane"
TRUSTED_PUB = HERE / "trusted.pub"

LOCAL_REGISTRY = "127.0.0.1:7777"
LOCAL_REPOSITORY = f"{LOCAL_REGISTRY}/local-dangerzone"


def subprocess_run(args, **kwargs):
    print(shlex.join(args))
    if "check" not in kwargs:
        kwargs["check"] = True
    return subprocess.run(args, **kwargs)


def validate_hash(ctx, param, value):
    if "@sha256:" not in value:
        raise click.BadParameter("Should contain a hash")
    return value


def get_image_hash(image):
    return image.split("@sha256:")[-1]


def get_repo(image):
    return image.split("@sha256")[0]


def get_blob_from_manifest(manifest):
    loaded_manifest = json.load(manifest.open())
    blobs = [layer["digest"] for layer in loaded_manifest["layers"]]

    if len(blobs) != 1:
        raise Exception("There should be exactly one blob. Bailing out")
    return blobs[0]


@contextmanager
def local_registry():
    """Start a local registry in a background process"""
    try:
        process = subprocess.Popen(
            [str(CRANE), "registry", "serve", "--address", LOCAL_REGISTRY]
        )
        yield process
    finally:
        process.terminate()


def ensure_installed():
    is_installed = COSIGN.exists() and ORAS.exists() and CRANE.exists()
    if not is_installed:
        click.echo(
            ("Error: Binaries are not installed. Please run mazette install"),
            err=True,
        )
        raise click.Abort()


def save_manifest_to(image_hash, destination):
    cmd_fetch_manifest = [
        str(ORAS),
        "manifest",
        "fetch",
        f"{LOCAL_REPOSITORY}:sha256-{image_hash}.sig",
        "--plain-http",
    ]

    process = subprocess_run(cmd_fetch_manifest, capture_output=True)

    with open(destination, "bw") as f:
        f.write(process.stdout)


def save_blob_to(blob, destination):
    subprocess_run(
        [
            str(ORAS),
            "blob",
            "fetch",
            f"{LOCAL_REPOSITORY}@{blob}",
            "--plain-http",
            "--output",
            str(destination),
        ],
    )


def cosign_verify(repository, on_local_repo=False):
    """Verifies that a signature is valid against a specified public key"""
    cmd_verify = [str(COSIGN), "verify", "-d", "--key", str(TRUSTED_PUB), repository]
    env = os.environ.copy()
    if on_local_repo:
        env["COSIGN_REPOSITORY"] = LOCAL_REPOSITORY
    subprocess_run(cmd_verify, env=env)


@click.group()
def cli():
    pass


@cli.command()
@click.argument("image", callback=validate_hash)
@click.option(
    "--signatures-dir", default="SIGNATURES", help="Base directory to store signatures"
)
@click.option("--key", help="Path to the signing key file")
@click.option("--sk", is_flag=True, help="Use a hardware security key for signing")
@click.option("--single-signature", is_flag=True, default=False)
def prepare(image, signatures_dir, key, sk, single_signature):
    """Prepare the signatures for the given IMAGE and saves them to a local folder"""
    ensure_installed()
    with local_registry():
        ret = prepare_signature(
            image,
            signatures_dir,
            key,
            sk,
            single_signature,
            date_folder=None,
            tag=True,
        )
    sys.exit(ret)


def prepare_signature(
    image, signatures_dir, key, sk, single_signature, date_folder=None, tag=False
):
    try:
        signatures_path = HERE / signatures_dir
        signatures_path.mkdir(parents=True, exist_ok=True)

        if not date_folder:
            now = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
            date_folder = signatures_path / now

        image_hash = get_image_hash(image)
        image_sig_dir = date_folder / image_hash
        image_sig_dir.mkdir(parents=True, exist_ok=True)

        # Write image reference to a file
        (image_sig_dir / "IMAGE").write_text(image)

        cmd_sign = [
            str(COSIGN),
            "sign",
            "-d",
            "-y",
        ]

        # Add key or hardware key option
        if sk:
            cmd_sign.append("--sk")
        elif key:
            cmd_sign.extend(["--key", key])
        else:
            raise click.Abort("Please provide either --key or --sk")

        # Add image to sign
        cmd_sign.append(image)

        # Execute signing to the local repository
        env = os.environ.copy()
        env["COSIGN_REPOSITORY"] = LOCAL_REPOSITORY
        subprocess_run(cmd_sign, env=env)

        # Ensure that the signatures are valid
        cosign_verify(image, on_local_repo=True)

        manifest = image_sig_dir / "MANIFEST"
        # Store the MANIFEST and the related blob to local files
        save_manifest_to(image_hash, manifest)

        blob = get_blob_from_manifest(manifest)
        save_blob_to(blob, image_sig_dir / "BLOB")

        if tag:
            (image_sig_dir / "LATEST").touch()

        if not single_signature:
            crane_cmd = [str(CRANE), "manifest", image]
            process = subprocess_run(crane_cmd, capture_output=True)
            digests = [m["digest"] for m in json.loads(process.stdout)["manifests"]]
            image_base = image.split("@sha256")[0]
            for digest in digests:
                sub_image = f"{image_base}@{digest}"
                prepare_signature(
                    sub_image,
                    signatures_dir,
                    key,
                    sk,
                    single_signature=True,
                    date_folder=date_folder,
                    tag=False,
                )

        click.echo(f"Signature prepared for {image}")
        return 0

    except subprocess.CalledProcessError as e:
        click.echo(f"Error preparing signature: {e}", err=True)
        return 1
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        return 1


def push_and_verify(
    source_dir,
    on_local_repo=True,
    tag_latest=False,
    check_all=False,
):
    """
    Push the prepared signatures to a (local) repository and verify their validity.
    """
    ensure_installed()

    # Get the latest active folder
    source_path = HERE / source_dir
    sorted_paths = [
        f for f in sorted(list(source_path.iterdir()), reverse=True) if f.is_dir()
    ]
    if not sorted_paths:
        click.echo("Nothing to verify, no valid path found")

    for index, date_path in enumerate(sorted_paths):
        for hash_dir in date_path.iterdir():
            if not hash_dir.is_dir():
                continue

            image_file = hash_dir / "IMAGE"
            manifest_file = hash_dir / "MANIFEST"
            blob_file = hash_dir / "BLOB"

            if image_file.exists() and manifest_file.exists():
                image = image_file.read_text().strip()
                repo = LOCAL_REPOSITORY if on_local_repo else get_repo(image)
                # Push the BLOB to the local registry
                blob = get_blob_from_manifest(manifest_file)
                cmd = [
                    str(ORAS),
                    "blob",
                    "push",
                    f"{repo}@{blob}",
                    str(blob_file),
                ]

                if on_local_repo:
                    cmd.append("--plain-http")

                subprocess_run(cmd)

                # Push the MANIFEST file to the local registry
                cmd = [
                    str(ORAS),
                    "manifest",
                    "push",
                    f"{repo}:sha256-{get_image_hash(image)}.sig",
                    str(manifest_file),
                ]

                if on_local_repo:
                    cmd.append("--plain-http")

                subprocess_run(
                    cmd,
                )

                cosign_verify(image, on_local_repo=on_local_repo)
                if index == 0 and (hash_dir / "LATEST").exists() and tag_latest:
                    subprocess_run([str(CRANE), "tag", image, "latest"])

        if not check_all:
            # we just want to iterate once
            break


@cli.command()
@click.option(
    "--source-dir",
    default="SIGNATURES",
    help="Directory with signature directories to publish",
)
def verify_local(source_dir):
    """Verifies that the to-be-published signatures match the trusted public key"""
    ensure_installed()
    with local_registry():
        push_and_verify(source_dir, on_local_repo=True, check_all=True)


@cli.command()
@click.option(
    "--source-dir",
    default="SIGNATURES",
    help="Directory with signature directories to publish",
)
def publish(source_dir):
    push_and_verify(source_dir, on_local_repo=False, tag_latest=True)


if __name__ == "__main__":
    cli()
