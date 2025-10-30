# Slack Block Kit message builders

import os
from typing import List, Dict, Any, Optional

def build_live_card(
    repo: str,
    branch: str,
    findings: List,
    pr_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build a Slack Block Kit message for IaC scan results.

    Args:
        repo: Repository name (e.g., "owner/repo")
        branch: Branch name
        findings: List of security findings
        pr_url: URL to the created PR (optional)

    Returns:
        Slack Block Kit message payload
    """

    blocks = []

    # Header block
    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": "🔒 AutoMCP IaC Security Scan"
        }
    })

    # Repository and branch info
    blocks.append({
        "type": "section",
        "fields": [
            {
                "type": "mrkdwn",
                "text": f"*Repository:*\n{repo}"
            },
            {
                "type": "mrkdwn",
                "text": f"*Branch:*\n{branch}"
            }
        ]
    })

    # Findings summary
    if findings:
        total_findings = len(findings)
        severity_counts = {}
        for finding in findings:
            # Handle both Finding objects and dicts
            if hasattr(finding, 'severity'):
                severity = str(finding.severity).lower()
            else:
                severity = finding.get("severity", "unknown").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        severity_text = ", ".join([f"{count} {severity}" for severity, count in severity_counts.items()])

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"⚠️ *{total_findings} security findings detected*\n{severity_text}"
            }
        })
    else:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "✅ *No security issues found*"
            }
        })

    # PR link
    if pr_url:
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "🔗 View PR"
                    },
                    "url": pr_url,
                    "style": "primary"
                }
            ]
        })

    # Footer
    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": "AutoMCP IaC Security Automation"
            }
        ]
    })

    return {"blocks": blocks}

def build_no_findings_message(repo: str, branch: str) -> Dict[str, Any]:
    """Build a message when no security issues are found"""
    blocks = []

    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": "✅ IaC Scan Complete - No Issues"
        }
    })

    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"Great! No security issues found in *{repo}* on branch *{branch}*."
        }
    })

    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": "AutoMCP IaC Security Scanner"
            }
        ]
    })

    return {"blocks": blocks}

def build_error_message(error: str, repo: Optional[str] = None) -> Dict[str, Any]:
    """Build an error message for Slack"""
    blocks = []

    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": "❌ IaC Scan Error"
        }
    })

    text = f"An error occurred during IaC scanning"
    if repo:
        text += f" for repository *{repo}*"
    text += f":\n```{error}```"

    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": text
        }
    })

    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": "AutoMCP IaC Security Scanner"
            }
        ]
    })

    return {"blocks": blocks}

def build_processing_message(repo: str, branch: str, commit_sha: str) -> Dict[str, Any]:
    """Build a processing start message"""
    blocks = []

    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": "🔍 Scanning IaC Files"
        }
    })

    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"Started scanning IaC files in *{repo}* on branch *{branch}*\nCommit: `{commit_sha[:8]}`"
        }
    })

    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": "AutoMCP IaC Security Scanner"
            }
        ]
    })

    return {"blocks": blocks}
