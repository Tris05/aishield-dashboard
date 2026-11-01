# AI Model and Dataset Security Policy

- Record model framework, artifact format, source, revision, checksum, license, intended use, limitations and training/fine-tuning provenance where available.
- Never import or execute model artifacts during a static repository scan. Use format-aware parsers in isolated processes with memory, CPU, file-size and time limits.
- Treat pickle-based formats as potentially executable during deserialization; artifact detection is a risk indicator, not proof of maliciousness.
- For datasets, examine provenance, access control, label/feature distributions, duplicates, split contamination and unexpected distribution changes. These checks are indicators and do not prove data poisoning.
- Adversarial robustness, membership inference, extraction and backdoor evaluations require controlled models/data and a threat-specific protocol. Do not claim these properties from hashes or static scans alone.
- Never upload model weights, datasets, prompts or source code to external services without explicit data-owner approval.
