# AI Threat Copilot

AI Threat Copilot is a personal security engineering project focused on threat modeling, cloud security analysis, and AI-assisted risk assessment for Kubernetes and multi-cloud environments.

The goal of the project is to combine traditional security engineering concepts such as STRIDE threat modeling and cloud security analysis with modern AI-assisted workflows that help explain, prioritise, and contextualise security findings.

Rather than replacing existing security tools, this platform is designed to work alongside them by ingesting findings from sources such as:

- Kubernetes security scanners
- AWS Security Hub
- Microsoft Defender for Cloud
- Google Security Command Center
- Runtime/container security tooling

The platform normalises findings into a common schema, maps risks to threat-modeling categories, and generates structured security analysis and remediation guidance.

---

## Current Features

- Multi-cloud finding ingestion
- Kubernetes security analysis
- STRIDE-based threat categorisation
- AI-assisted risk enrichment
- AI-generated remediation guidance
- FastAPI backend
- Structured JSON responses
- Security finding normalisation pipeline

---

## Planned Features

- MITRE ATT&CK mapping
- RAG-based security knowledgebase
- Falco runtime detection ingestion
- Trivy integration
- Mermaid attack-path diagrams
- OCI deployment
- Dashboard and reporting UI
- CI/CD integration

---

## Tech Stack

- Python
- FastAPI
- Pydantic
- OpenAI APIs
- Kubernetes
- Cloud Security
- OCI (planned)

---

## Configuration

Do not hardcode API keys in the application.

Set your OpenAI API key as an environment variable:

```bash
export OPENAI_API_KEY="your_api_key_here"
```

For local development, you can also copy `.env.example` to `.env` and set
the value there. `.env` is ignored by Git and should not be committed.

---

## Architecture Overview

Security findings are ingested from cloud and Kubernetes security tooling, normalised into a common internal format, enriched with threat-modeling context, and passed through an AI-assisted analysis layer to generate prioritised security insights and remediation guidance.

```text
Security Tools
↓
Normalization Layer
↓
Threat Correlation
↓
STRIDE Mapping
↓
AI-Assisted Analysis
↓
Remediation Guidance

## Documentation

- [Architecture Overview](./docs/architecture.md)
