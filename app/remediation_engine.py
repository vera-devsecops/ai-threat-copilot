def generate_remediation(finding):
    text = f"{finding.issue} {finding.description}".lower()

    if "privilege" in text or "admin" in text:
        return "Review and reduce privileged access. Apply least privilege and remove unnecessary admin permissions."

    if "public" in text or "exposed" in text:
        return "Restrict public exposure, review access controls, and confirm the resource should not be internet-accessible."

    if "critical" in finding.severity.lower() or "vulnerability" in text:
        return "Prioritize patching or replacing the vulnerable component and verify exploitability."

    if "shell" in text or "runtime" in text:
        return "Investigate runtime activity, review container logs, and isolate the workload if compromise is suspected."

    return "Review the finding manually and prioritize remediation based on exposure, privilege, and business impact."