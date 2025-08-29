package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type Config struct {
	Image      string
	Platform   string
	OutputDir  string
	OutputFile string
	Format     string
	Verbose    bool
}

type AttestationManifest struct {
	SchemaVersion int                    `json:"schemaVersion"`
	MediaType     string                 `json:"mediaType"`
	Config        map[string]interface{} `json:"config"`
	Layers        []Layer                `json:"layers"`
}

type Layer struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
}

type ImageIndex struct {
	SchemaVersion int        `json:"schemaVersion"`
	MediaType     string     `json:"mediaType"`
	Manifests     []Manifest `json:"manifests"`
}

type Manifest struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *Platform         `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type InTotoAttestation struct {
	PredicateType string      `json:"predicateType"`
	Predicate     interface{} `json:"predicate"`
}

func main() {
	config := parseFlags()

	if config.Verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetFlags(0)
	}

	if err := extractSBOM(config); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.Image, "image", "", "Container image reference (required)")
	flag.StringVar(&config.Platform, "platform", "", "Platform (e.g., linux/amd64)")
	flag.StringVar(&config.OutputDir, "output-dir", "sboms", "Output directory for extracted SBOMs")
	flag.StringVar(&config.OutputFile, "output", "", "Output file (stdout if not specified)")
	flag.StringVar(&config.Format, "format", "json", "Output format: json, raw")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "sbom-extractor - Extract SBOMs from container image attestations\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <image>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s quay.io/kairos/ubuntu:22.04-standard-amd64-generic-v3.5.2-k3s-v1.33.4-k3s1\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --platform linux/amd64 --output sbom.json quay.io/kairos/ubuntu:latest\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Get image from positional argument if not provided via flag
	if config.Image == "" && flag.NArg() > 0 {
		config.Image = flag.Arg(0)
	}

	if config.Image == "" {
		flag.Usage()
		os.Exit(1)
	}

	return config
}

func extractSBOM(config *Config) error {
	log.Printf("Extracting SBOM from image: %s", config.Image)

	// Parse image reference
	ref, err := name.ParseReference(config.Image)
	if err != nil {
		return fmt.Errorf("invalid image reference: %w", err)
	}

	// Get subject digest
	subjectDigest, err := getSubjectDigest(ref, config.Platform)
	if err != nil {
		return fmt.Errorf("failed to get subject digest: %w", err)
	}

	if config.Verbose {
		log.Printf("Subject digest: %s", subjectDigest)
	}

	// Find attestation manifests
	attestationDigests, err := findAttestationManifests(ref, subjectDigest)
	if err != nil {
		return fmt.Errorf("failed to find attestation manifests: %w", err)
	}

	if len(attestationDigests) == 0 {
		return fmt.Errorf("no SBOM attestations found for image %s", config.Image)
	}

	log.Printf("Found %d attestation manifest(s)", len(attestationDigests))

	// Create output directory
	if config.OutputFile == "" {
		if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Extract SBOMs from each attestation
	for i, attestationDigest := range attestationDigests {
		if config.Verbose {
			log.Printf("Processing attestation %d: %s", i+1, attestationDigest)
		}

		sbomData, err := extractSBOMFromAttestation(ref, attestationDigest)
		if err != nil {
			log.Printf("Warning: failed to extract SBOM from attestation %s: %v", attestationDigest, err)
			continue
		}

		// Determine output file
		var outputPath string
		if config.OutputFile != "" {
			outputPath = config.OutputFile
		} else {
			fileName := fmt.Sprintf("%s.sbom.json", strings.TrimPrefix(attestationDigest, "sha256:"))
			outputPath = filepath.Join(config.OutputDir, fileName)
		}

		// Write SBOM data
		if config.OutputFile == "" || config.OutputFile == "-" {
			fmt.Print(string(sbomData))
		} else {
			if err := os.WriteFile(outputPath, sbomData, 0644); err != nil {
				return fmt.Errorf("failed to write SBOM file: %w", err)
			}
			log.Printf("Wrote SBOM to: %s", outputPath)
		}

		// If single output file specified, only process first SBOM
		if config.OutputFile != "" {
			break
		}
	}

	return nil
}

func getSubjectDigest(ref name.Reference, platform string) (string, error) {
	// If reference already contains a digest, use it
	if digest, ok := ref.(name.Digest); ok {
		return digest.DigestStr(), nil
	}

	// Get the digest for the reference
	desc, err := remote.Get(ref)
	if err != nil {
		return "", err
	}

	// If platform specified, resolve platform-specific digest
	if platform != "" {
		plat := parsePlatform(platform)
		if plat != nil {
			img, err := remote.Image(ref, remote.WithPlatform(*plat))
			if err != nil {
				return "", err
			}
			digest, err := img.Digest()
			if err != nil {
				return "", err
			}
			return digest.String(), nil
		}
	}

	return desc.Digest.String(), nil
}

func parsePlatform(platform string) *v1.Platform {
	plat, err := v1.ParsePlatform(platform)
	if err != nil {
		return nil
	}
	return plat
}

func findAttestationManifests(ref name.Reference, subjectDigest string) ([]string, error) {
	// Try to get the image index/manifest list
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}

	var index ImageIndex
	if err := json.Unmarshal(desc.Manifest, &index); err != nil {
		return nil, fmt.Errorf("failed to parse image index: %w", err)
	}

	var attestationDigests []string
	for _, manifest := range index.Manifests {
		// Check if this is an attestation manifest
		if refType, ok := manifest.Annotations["vnd.docker.reference.type"]; ok && refType == "attestation-manifest" {
			// Check if it references our subject (if digest specified)
			if refDigest, ok := manifest.Annotations["vnd.docker.reference.digest"]; ok {
				if refDigest == subjectDigest {
					attestationDigests = append(attestationDigests, manifest.Digest)
				}
			} else {
				// If no specific subject reference, include it anyway
				attestationDigests = append(attestationDigests, manifest.Digest)
			}
		}
	}

	return attestationDigests, nil
}

func extractSBOMFromAttestation(ref name.Reference, attestationDigest string) ([]byte, error) {
	// Create reference to the attestation manifest
	repo := ref.Context()
	attestationRef, err := name.NewDigest(repo.String() + "@" + attestationDigest)
	if err != nil {
		return nil, err
	}

	// Get the attestation manifest
	desc, err := remote.Get(attestationRef)
	if err != nil {
		return nil, err
	}

	var attestationManifest AttestationManifest
	if err := json.Unmarshal(desc.Manifest, &attestationManifest); err != nil {
		return nil, fmt.Errorf("failed to parse attestation manifest: %w", err)
	}

	// Find SBOM layer
	for _, layer := range attestationManifest.Layers {
		if predicateType, ok := layer.Annotations["in-toto.io/predicate-type"]; ok {
			if strings.Contains(strings.ToLower(predicateType), "spdx") ||
				strings.Contains(strings.ToLower(predicateType), "cyclonedx") ||
				strings.Contains(strings.ToLower(predicateType), "syft") {

				// Get the layer blob
				layerRef, err := name.NewDigest(repo.String() + "@" + layer.Digest)
				if err != nil {
					return nil, err
				}

				blob, err := remote.Layer(layerRef)
				if err != nil {
					return nil, err
				}

				reader, err := blob.Compressed()
				if err != nil {
					return nil, err
				}
				defer reader.Close()

				// Read the attestation data
				var attestationData []byte
				buf := make([]byte, 1024)
				for {
					n, err := reader.Read(buf)
					if n > 0 {
						attestationData = append(attestationData, buf[:n]...)
					}
					if err != nil {
						break
					}
				}

				// Try to parse as in-toto attestation
				var attestation InTotoAttestation
				if err := json.Unmarshal(attestationData, &attestation); err == nil && attestation.PredicateType != "" {
					// Extract predicate (the actual SBOM)
					predicateData, err := json.MarshalIndent(attestation.Predicate, "", "  ")
					if err != nil {
						return nil, fmt.Errorf("failed to marshal predicate: %w", err)
					}
					return predicateData, nil
				}

				// Return raw data if not in-toto format
				return attestationData, nil
			}
		}
	}

	return nil, fmt.Errorf("no SBOM layer found in attestation")
}
