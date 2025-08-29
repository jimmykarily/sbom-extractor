# sbom-extractor

NOTE: This is a vide-coded conversion of this bash script: https://github.com/kairos-io/kairos/issues/3615#issuecomment-3219538696

A simple tool to extract pre-attached SBOMs from container image OCI attestations.

## Why?

Existing tools either generate SBOMs from scratch or have complex interfaces. This tool does one thing well: extract SBOMs that were already attached to container images as OCI attestations during the build process.

## Installation

```bash
go install github.com/kairos-io/sbom-extractor@latest
```

Or build from source:

```bash
git clone https://github.com/kairos-io/sbom-extractor
cd sbom-extractor
go build -o sbom-extractor .
```

## Usage

Basic usage:
```bash
sbom-extractor quay.io/kairos/ubuntu:22.04-standard-amd64-generic-v3.5.2-k3s-v1.33.4-k3s1
```

With platform specification:
```bash
sbom-extractor --platform linux/amd64 quay.io/kairos/ubuntu:latest
```

Save to specific file:
```bash
sbom-extractor --output sbom.json quay.io/kairos/ubuntu:latest
```

Verbose output:
```bash
sbom-extractor --verbose quay.io/kairos/ubuntu:latest
```

## Options

- `--platform`: Specify platform (e.g., linux/amd64)
- `--output`: Output file (stdout if not specified)
- `--output-dir`: Output directory for extracted SBOMs (default: sboms)
- `--format`: Output format: json, raw (default: json)
- `--verbose`: Verbose output

## What it does

1. Parses the container image reference
2. Finds attestation manifests attached to the image
3. Extracts SBOM data from attestation layers
4. Handles both in-toto attestation format and raw SBOM data
5. Outputs clean SBOM JSON

## Supported SBOM formats

- SPDX
- CycloneDX  
- Syft
- Any format stored as OCI attestation

## Why not use existing tools?

- **Docker Scout**: Generates SBOMs, doesn't extract pre-attached ones
- **Syft**: Generates SBOMs from image analysis
- **Trivy**: Generates SBOMs from image analysis  
- **Cosign**: Has deprecated SBOM support, complex interface
- **crane**: Low-level, requires manual JSON parsing

This tool fills the gap by providing a simple interface specifically for extracting publisher-provided SBOMs.
