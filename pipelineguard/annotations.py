"""GitHub workflow annotations without source snippets or secret values."""


def escape_message(value):
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(value):
    return escape_message(value).replace(":", "%3A").replace(",", "%2C")


def github_annotations(report):
    lines = []
    for finding in report["findings"]:
        level = "error" if finding.get("severity") == "CRITICAL" else "warning"
        properties = ["title=PipelineGuard"]
        if finding.get("file"):
            properties.append("file=" + escape_property(finding["file"]))
        line = finding.get("line")
        if type(line) is int and line > 0:
            properties.append("line=" + str(line))
        message = finding.get("rule", "Security finding")
        if finding.get("id"):
            message += ": " + str(finding["id"])
        lines.append(f"::{level} {','.join(properties)}::{escape_message(message)}")
    if report.get("policy_blocked"):
        lines.append("::error title=PipelineGuard::Release blocked by configured policy")
    return lines
