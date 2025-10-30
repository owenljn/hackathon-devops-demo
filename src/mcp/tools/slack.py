# Slack Reporting Tool

import os
import json
import logging
from typing import Optional

from ..schemas import SlackReportInput, SlackReportResponse, Finding, Severity

logger = logging.getLogger(__name__)

async def run_slack_report(report_input: SlackReportInput) -> SlackReportResponse:
    """Send scan results to Slack webhook"""
    logger.info(f"Sending Slack report for {report_input.repo}")

    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        return SlackReportResponse(
            success=False,
            message="SLACK_WEBHOOK_URL environment variable not set"
        )

    try:
        import requests
    except ImportError:
        return SlackReportResponse(
            success=False,
            message="requests library not available"
        )

    # Build message payload
    if report_input.findings:
        # Findings found - show results with PR link
        from ...gateway.render import build_live_card
        message = build_live_card(
            repo=report_input.repo,
            branch=report_input.branch,
            findings=report_input.findings,
            pr_url=report_input.pr_url
        )
    else:
        # No findings - show success message
        from ...gateway.render import build_no_findings_message
        message = build_no_findings_message(
            repo=report_input.repo,
            branch=report_input.branch
        )

    # Add channel override if specified
    payload = message
    if hasattr(report_input, 'channel') and report_input.channel:
        payload = {**message, "channel": report_input.channel}
    elif os.getenv("ALERT_CHANNEL"):
        payload = {**message, "channel": os.getenv("ALERT_CHANNEL")}

    # Send to Slack
    headers = {'Content-Type': 'application/json'}
    response = requests.post(webhook_url, json=payload, headers=headers)

    if response.status_code == 200:
        return SlackReportResponse(
            success=True,
            message="Slack message sent successfully"
        )
    else:
        logger.error(f"Slack webhook failed: {response.status_code} - {response.text}")
        return SlackReportResponse(
            success=False,
            message=f"Slack webhook failed with status {response.status_code}"
        )
