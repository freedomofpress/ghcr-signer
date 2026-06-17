# /// script
# dependencies = [
#     "click",
#     "requests",
# ]
# ///

import json
import shlex
import subprocess
from pathlib import Path

import click
import requests

HERE = Path(__file__).parent
CRANE = HERE / "assets" / "crane" / "crane"

CVES_DASHBOARD = "https://cves.dangerzone.rocks"
LATEST_CVES_URL = f"{CVES_DASHBOARD}/grype.json"
NIGHTLY_CVES_URL = f"{CVES_DASHBOARD}/nightly/grype.json"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

CHECKLIST = """\
## Checklist

- [ ] Make sure that the above digests are the latest ones in https://ghcr.io/freedomofpress/dangerzone/v1.
- [ ] The image is the latest one built by our CI
- [ ] The CI tests pass for this image
- [ ] Grype does not report any security vulnerabilities for this image that can be fixed, or any Critical vulnerabilities in general
"""


def find_latest_signatures_dir(signatures_dir):
    """Find the most recent directory with signatures."""
    signatures_path = Path(signatures_dir)
    click.echo(f"Scanning {signatures_dir} for latest signature directory...", err=True)
    dirs = [d for d in signatures_path.iterdir() if d.is_dir()]
    latest = sorted(dirs, reverse=True)[0]
    click.echo(f"Latest signature directory: {latest.name}", err=True)
    return latest


def identify_images(latest_dir):
    """Distinguish the root manifest from the platform manifests.

    Find the root manifest in the signatures directory, by looking for the
    `LATEST` marker. The rest of the manifests should be the platform ones.
    """
    click.echo(
        f"Identifying root and platform images in {latest_dir.name}...", err=True
    )
    hash_dirs = sorted([d for d in latest_dir.iterdir() if d.is_dir()])
    if not hash_dirs:
        raise click.ClickException(f"No image directories in {latest_dir}")

    root_dir = None
    platform_dirs = []

    for d in hash_dirs:
        if (d / "LATEST").exists():
            root_dir = d
        else:
            platform_dirs.append(d)

    if root_dir is None:
        raise click.ClickException(f"No LATEST marker found in {latest_dir}")
    if len(platform_dirs) != 2:
        raise click.ClickException(
            f"Found more than two platform images: {', '.join(d.name for d in platform_dirs)}",
            err=True,
        )

    click.echo(f"  Root image digest: {root_dir.name}", err=True)
    click.echo("  Platform image digests:", err=True)
    click.echo(f"  - {platform_dirs[0].name}", err=True)
    click.echo(f"  - {platform_dirs[1].name}", err=True)
    return root_dir, platform_dirs


def read_image_ref(image_dir):
    """Get the image reference from the directories."""
    image_file = image_dir / "IMAGE"
    if not image_file.exists():
        raise click.ClickException(f"IMAGE file not found in {image_dir}")
    ref = image_file.read_text().strip()
    click.echo(f"  Read image reference: {ref[:80]}...", err=True)
    return ref


def run_crane(args):
    """Run the crane command."""
    cmd = [str(CRANE)] + args
    cmd_preview = shlex.join(cmd)
    click.echo(f"  Running: {cmd_preview}", err=True)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=True)
    return result.stdout.strip()


def lookup_platforms_with_crane(root_ref, platform_dirs):
    """Retrieve the architecture of a platform manifest from the root manifest."""
    click.echo("Fetching multi-arch manifest to identify platforms...", err=True)
    manifest_output = run_crane(["manifest", root_ref])

    try:
        manifest = json.loads(manifest_output)
    except json.JSONDecodeError:
        raise click.ClickException("Failed to parse manifest JSON")

    manifests = manifest.get("manifests", [])
    if not manifests:
        raise click.ClickException("No platform manifests found in multi-arch image")

    arch_map = {}
    for entry in manifests:
        platform = entry.get("platform", {})
        arch = platform.get("architecture", "")
        os_name = platform.get("os", "")
        entry_digest = entry["digest"].replace("sha256:", "")
        if arch and os_name:
            arch_map[entry_digest] = f"{os_name}/{arch}"

    result = {}
    for d in platform_dirs:
        if d.name in arch_map:
            result[d.name] = arch_map[d.name]
            click.echo(f"  {d.name[:12]}... → {arch_map[d.name]}", err=True)
        else:
            result[d.name] = None
            click.echo(f"  {d.name[:12]}... → unknown platform", err=True)

    return result


def find_smallest_logindex(latest_dir):
    """Find the smallest logIndex across all MANIFEST files in the signatures dir."""
    click.echo(
        f"Extracting logIndex values from {latest_dir.name}...", err=True
    )
    hash_dirs = sorted([d for d in latest_dir.iterdir() if d.is_dir()])
    min_index = float("inf")

    for d in hash_dirs:
        manifest_file = d / "MANIFEST"
        if not manifest_file.exists():
            continue
        try:
            manifest = json.loads(manifest_file.read_text())
            bundle_str = (
                manifest.get("layers", [{}])[0]
                .get("annotations", {})
                .get("dev.sigstore.cosign/bundle", "")
            )
            if not bundle_str:
                continue
            bundle = json.loads(bundle_str)
            log_index = bundle.get("Payload", {}).get("logIndex", -1)
            if log_index < min_index:
                min_index = log_index
        except (json.JSONDecodeError, KeyError, IndexError):
            continue

    return min_index


def generate_build_info(date, root_ref, platform_info, platform_dirs):
    lines = []
    lines.append(
        f"This PR updates the Dangerzone container image to the `{date}` build.\n"
    )
    lines.append("\n")
    lines.append("## Build info\n")
    lines.append("\n")
    lines.append(f"- Root image: `{root_ref}`\n")

    for d in sorted(platform_dirs, key=lambda x: x.name):
        platform_label = platform_info.get(d.name)
        if platform_label is None:
            platform_label = f"platform ({d.name[:12]}...)"
        platform_ref = read_image_ref(d)
        lines.append(f"- `{platform_label}` image: `{platform_ref}`\n")

    return "".join(lines)


def fetch_grype_json(url):
    click.echo(f"  Fetching {url}...", err=True)
    data = requests.get(url, timeout=30).json()
    return parse_grype_data(data)


def parse_grype_data(data):
    matches = data.get("matches", [])
    result = {}

    for match in matches:
        vuln = match.get("vulnerability", {})
        severity = vuln.get("severity", "Unknown")
        cve_id = vuln.get("id", "")
        fix_state = vuln.get("fix", {}).get("state", "")

        if not cve_id:
            continue

        if severity not in result:
            result[severity] = {}

        if cve_id not in result[severity]:
            result[severity][cve_id] = {
                # fix_state is usually wont-fix, not-fixed
                "fix_state": fix_state,
            }

    return result


def compare_cves(latest, nightly):
    fixed_cves = {}
    pending_cves = {}

    for severity in SEVERITY_ORDER:
        _latest_cves = set(latest.get(severity, {}).keys())
        _nightly_cves = set(nightly.get(severity, {}).keys())

        # In order to find out if a CVE has been fixed, we need to check if it
        # still exists in the CVE report of the nightly image.
        fixed_cves[severity] = _latest_cves - _nightly_cves

        # Some CVEs that remain in the nightly image may be marked as wont-fix
        # by Debian. There are others though that are more important, and will
        # not be marked as such by Debian. In this function, we want to report
        # the latter category.
        pending_cves[severity] = {
            cve
            for cve in _nightly_cves
            if nightly[severity][cve]["fix_state"] != "wont-fix"
        }

    return fixed_cves, pending_cves


def generate_cve_section(title, cve_by_severity):
    total = sum(len(v) for v in cve_by_severity.values())
    lines = []

    if total == 0:
        lines.append(f"## No {title.lower()}\n")
        return "".join(lines)

    lines.append("<details>\n")
    lines.append(f"<summary><h3>{title} ({total})</h3></summary>\n")
    lines.append("\n")

    for severity in SEVERITY_ORDER:
        cves = cve_by_severity.get(severity, {})
        if not cves:
            continue

        lines.append(f"### {severity}\n")
        lines.append("\n")
        for cve_id in sorted(cves):
            url = f"https://security-tracker.debian.org/tracker/{cve_id}"
            lines.append(f"* [{cve_id}]({url})\n")
        lines.append("\n")

    lines.append("</details>\n")

    return "".join(lines)


@click.command()
@click.option(
    "--signatures-dir",
    default="SIGNATURES",
    show_default=True,
    help="Directory with container signatures",
)
@click.option(
    "--output",
    default=None,
    help="Output Markdown file (default: stdout)",
)
def cli(signatures_dir, output):
    """Generate a Markdown report with container build info and CVE comparison."""

    click.echo("=== Dangerzone Container Report Generator ===", err=True)
    click.echo("", err=True)

    latest_dir = find_latest_signatures_dir(signatures_dir)
    root_dir, platform_dirs = identify_images(latest_dir)
    date_str = latest_dir.name[:10]
    click.echo(f"Build date: {date_str}", err=True)

    click.echo("\nReading image references...", err=True)
    root_ref = read_image_ref(root_dir)

    platform_info = {}
    click.echo("\nResolving platform architectures...", err=True)
    platform_info = lookup_platforms_with_crane(root_ref, platform_dirs)

    click.echo("\nFinding smallest logIndex...", err=True)
    min_logindex = find_smallest_logindex(latest_dir)
    click.echo(f"  Smallest logIndex: {min_logindex}", err=True)

    click.echo("\nGenerating build info section...", err=True)
    build_info = generate_build_info(date_str, root_ref, platform_info, platform_dirs)
    build_info += f"\n- Smallest Rekor logIndex: `{min_logindex}`\n"

    click.echo("\nFetching vulnerability scans...", err=True)
    latest_cves = fetch_grype_json(LATEST_CVES_URL)
    nightly_cves = fetch_grype_json(NIGHTLY_CVES_URL)

    total_latest = sum(len(v) for v in latest_cves.values())
    total_nightly = sum(len(v) for v in nightly_cves.values())
    click.echo(f"  Latest:  {total_latest} unique CVE(s)", err=True)
    click.echo(f"  Nightly: {total_nightly} unique CVE(s)", err=True)

    click.echo("Comparing CVEs...", err=True)
    fixed, pending = compare_cves(latest_cves, nightly_cves)

    click.echo(f"  Fixed:       {len(fixed)} CVE(s)", err=True)
    click.echo(f"  Pending fix: {len(pending)} CVE(s)", err=True)

    click.echo("Generating CVE report sections...", err=True)
    cve_report = "## CVEs\n\n"
    cve_report += generate_cve_section("Fixed", fixed)
    cve_report += "\n"
    cve_report += generate_cve_section("Pending fixes", pending)

    report = build_info + "\n" + cve_report + "\n" + CHECKLIST

    if output:
        Path(output).write_text(report)
        click.echo(f"Report written to {output}", err=True)
    else:
        click.echo(report)


if __name__ == "__main__":
    cli()
