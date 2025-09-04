# /// script
# dependencies = [
#     "click",
# ]
# ///

import json
import shutil
import subprocess
from pathlib import Path

import click


def validate_hash(ctx, param, value):
    if "@sha256:" not in value:
        raise click.BadParameter("Should contain a hash")
    return value


def ensure_installed(binary):
    try:
        subprocess.run(["which", binary], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        click.echo(
            f"Error: cosign is not installed. Please install {binary} first.", err=True
        )
        raise click.Abort()


@click.group()
def cli():
    pass


@cli.command()
@click.argument("image", callback=validate_hash)
@click.option(
    "--signatures-dir", default="TO_PUBLISH", help="Base directory to store signatures"
)
@click.option("--key", help="Path to the signing key file")
@click.option("--sk", is_flag=True, help="Use a hardware security key for signing")
@click.option("--recursive", is_flag=True)
def prepare(image, signatures_dir, key, sk, recursive):
    """Prepare the signatures for the given IMAGE and saves them to a local folder"""
    ensure_installed("cosign")
    if recursive:
        ensure_installed("crane")
    prepare_signature(image, signatures_dir, key, sk, recursive)


def prepare_signature(image, signatures_dir, key, sk, recursive):
    try:
        signatures_path = Path(signatures_dir)
        signatures_path.mkdir(parents=True, exist_ok=True)

        image_hash = image.split("@sha256:")[-1]
        image_sig_dir = signatures_path / image_hash
        image_sig_dir.mkdir(parents=True, exist_ok=True)

        # Write image reference to a file
        (image_sig_dir / "IMAGE").write_text(image)

        payload_file = image_sig_dir / "payload.json"
        generate_cmd = ["cosign", "generate", image]
        with payload_file.open("w") as payload_out:
            subprocess.run(generate_cmd, check=True, stdout=payload_out)

        # Prepare sign command based on key type
        sign_cmd = [
            "cosign",
            "sign",
            "-d",
            "--upload=false",
            "-y",
            "--output-signature",
            str(image_sig_dir / "signature"),
            "--output-certificate",
            str(image_sig_dir / "certificate"),
            "--payload",
            str(payload_file),
        ]

        # Add key or hardware key option
        if sk:
            sign_cmd.append("--sk")
        elif key:
            sign_cmd.extend(["--key", key])
        else:
            raise click.Abort("Please provide either --key or --sk")

        # Add image to sign
        sign_cmd.append(image)

        # Execute signing
        subprocess.run(sign_cmd, check=True)

        if recursive:
            crane_cmd = ["crane", "manifest", image]
            process = subprocess.run(crane_cmd, check=True, capture_output=True)
            digests = [m["digest"] for m in json.loads(process.stdout)["manifests"]]
            image_base = image.split("@sha256")[0]
            for digest in digests:
                sub_image = f"{image_base}@{digest}"
                prepare_signature(sub_image, signatures_dir, key, sk, False)

        click.echo(f"Signature prepared for {image}")
        return 0

    except subprocess.CalledProcessError as e:
        click.echo(f"Error preparing signature: {e}", err=True)
        return 1
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        return 1


@cli.command()
@click.option(
    "--source-dir",
    default="TO_PUBLISH",
    help="Directory with signature directories to publish",
)
@click.option(
    "--pub-key",
    default="trusted.pub",
    help="Location of the public key",
    type=click.Path(exists=True),
)
def verify(source_dir, pub_key):
    """Verifies that the to-be-published signatures match the trusted public key"""
    ensure_installed("cosign")
    source_path = Path(source_dir)
    for hash_dir in source_path.iterdir():
        if not hash_dir.is_dir():
            continue

        image_file = hash_dir / "IMAGE"
        payload_file = hash_dir / "payload.json"
        signature_file = hash_dir / "signature"

        if image_file.exists() and payload_file.exists() and signature_file.exists():
            image = image_file.read_text().strip()

            verify_cmd = [
                "cosign",
                "verify-blob",
                "--key",
                pub_key,
                "--signature",
                str(signature_file),
                str(payload_file),
            ]

            try:
                subprocess.run(verify_cmd, check=True)
                click.echo(f"Successfully verified signatures for {image}")

            except subprocess.CalledProcessError as e:
                click.echo(f"Error validating signatures for {image}: {e}", err=True)


@cli.command()
@click.option(
    "--source-dir",
    default="TO_PUBLISH",
    help="Directory with signature directories to publish",
)
@click.option(
    "--published-dir",
    default="PUBLISHED",
    help="Destination directory for the published signatures",
)
def publish(source_dir, published_dir):
    ensure_installed("cosign")
    source_path = Path(source_dir)

    published_path = Path(published_dir)
    published_path.mkdir(parents=True, exist_ok=True)

    # Check if source directory is empty
    if not source_path.exists():
        click.echo(f"""Skipping as the "{str(source_path)}" folder does not exist""")
        return 0

    for hash_dir in source_path.iterdir():
        if not hash_dir.is_dir():
            continue

        image_file = hash_dir / "IMAGE"
        payload_file = hash_dir / "payload.json"
        signature_file = hash_dir / "signature"

        if image_file.exists() and payload_file.exists() and signature_file.exists():
            image = image_file.read_text().strip()

            try:
                # Attach signature
                attach_cmd = [
                    "cosign",
                    "attach",
                    "signature",
                    "--payload",
                    str(payload_file),
                    "--signature",
                    str(signature_file),
                    image,
                ]
                subprocess.run(attach_cmd, check=True)

                # Move to PUBLISHED directory
                shutil.move(str(hash_dir), str(published_path / hash_dir.name))
                click.echo(f"Successfully published signature for {image}")

            except subprocess.CalledProcessError as e:
                click.echo(f"Error publishing signature for {image}: {e}", err=True)
                raise click.Abort()


if __name__ == "__main__":
    cli()
