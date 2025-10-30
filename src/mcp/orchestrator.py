# MCP Orchestrator - Coordinates the IaC security pipeline

import logging
from typing import List, Optional

from .schemas import (
    PushEvent, IACScanInput, IACScanResponse, AIFixInput, AIFixResponse,
    PRCreateInput, PRCreateResponse, SlackReportInput, SlackReportResponse,
    PRSpec, Finding
)
from .server import mcp_server

# Import tools
from .tools import iac_scan, ai_fix, pr, slack

logger = logging.getLogger(__name__)

async def run_iac_scan(scan_input: IACScanInput) -> IACScanResponse:
    """Run IaC scanning through MCP server"""
    return await mcp_server.run_tool("iac_scan", scan_input=scan_input)

async def run_ai_fix(fix_input: AIFixInput) -> AIFixResponse:
    """Run AI fix generation through MCP server"""
    return await mcp_server.run_tool("ai_fix", fix_input=fix_input)

async def run_pr_create(pr_input: PRCreateInput) -> PRCreateResponse:
    """Run PR creation through MCP server"""
    return await mcp_server.run_tool("pr_create", pr_input=pr_input)

async def run_slack_report(report_input: SlackReportInput) -> SlackReportResponse:
    """Run Slack reporting through MCP server"""
    return await mcp_server.run_tool("slack_report", report_input=report_input)

def register_tools():
    """Register all tools with the MCP server"""
    mcp_server.register_tool("iac_scan", iac_scan.run_iac_scan)
    mcp_server.register_tool("ai_fix", ai_fix.run_ai_fix)
    mcp_server.register_tool("pr_create", pr.run_pr_create)
    mcp_server.register_tool("slack_report", slack.run_slack_report)

    logger.info("All MCP tools registered")

async def handle_push_event(push_event: dict):
    """
    Handle a GitHub push event by orchestrating the security scan pipeline

    Args:
        push_event: Normalized push event data
    """
    logger.info(f"Handling push event: {push_event}")

    repo = push_event["repo"]
    branch = push_event["branch"]
    commit_sha = push_event["commit_sha"]
    changed_paths = push_event.get("changed_paths", [])

    # Step 1: Check for duplicates (idempotency)
    from ..gateway.state import is_duplicate_event, store_push_event, update_event_status
    if is_duplicate_event(repo, commit_sha):
        logger.info("Ignoring duplicate push event")
        return

    # Store event for tracking
    event_id = store_push_event(repo, branch, commit_sha, changed_paths)
    update_event_status(event_id, "processing")

    try:
        # Step 2: Run IaC Security Scan
        scan_input = IACScanInput(
            directory=".",
            file_patterns=["*.tf", "*.bicep", "*.yaml", "*.yml", "*.json"],
            excluded_patterns=[]
        )

        scan_response = await run_iac_scan(scan_input)

        if not scan_response.success:
            logger.error(f"Scan failed: {scan_response.message}")
            update_event_status(event_id, "scan_failed", error=scan_response.message)
            # Still send Slack notification about the error
            await run_slack_report(SlackReportInput(
                repo=repo,
                branch=branch,
                findings=[],
                pr_url=None
            ))
            return

        findings = scan_response.scan_result.findings if scan_response.scan_result else []
        logger.info(f"Scan complete: {len(findings)} findings")

        # Step 3: If no findings, report success and exit
        if not findings:
            logger.info("No security issues found")
            update_event_status(event_id, "completed", findings_count=0)

            await run_slack_report(SlackReportInput(
                repo=repo,
                branch=branch,
                findings=[],
                pr_url=None
            ))
            return

        # Step 4: Generate AI fixes for findings
        fix_input = AIFixInput(
            findings=findings,
            source_directory="."
        )

        fix_response = await run_ai_fix(fix_input)

        if not fix_response.success:
            logger.error(f"AI fix generation failed: {fix_response.message}")
            update_event_status(event_id, "fix_failed", error=fix_response.message)
            return

        patches = fix_response.patches
        logger.info(f"Generated {len(patches)} patches")

        # Step 5: Create PR with fixes
        pr_spec = PRSpec(
            title=f"🔒 Automated IaC Security Fixes - {commit_sha[:8]}",
            body=f"""## Automated Security Fixes

This PR contains automated fixes for Infrastructure as Code security issues detected in commit {commit_sha[:8]}.

### Findings Fixed ({len(findings)} issues):
""" + "\n".join([f"- **{f.severity.upper()}:** {f.check_name}" for f in findings[:10]]) + # Show first 10
(f"\n... and {len(findings) - 10} more" if len(findings) > 10 else "") +
"""

### Applied Fixes:
""" + "\n".join([f"- {p.description}" for p in patches]),

            head_branch=f"autofix/{commit_sha[:8]}",
            base_branch="main",
            draft=False
        )

        pr_input = PRCreateInput(
            repo=repo,
            branch_name=pr_spec.head_branch,
            patches=patches,
            pr_spec=pr_spec
        )

        pr_response = await run_pr_create(pr_input)

        if not pr_response.success:
            logger.error(f"PR creation failed: {pr_response.message}")
            update_event_status(event_id, "pr_failed", error=pr_response.message)
            return

        pr_url = pr_response.pr_url
        logger.info(f"PR created: {pr_url}")
        update_event_status(event_id, "completed", pr_url=pr_url, findings_count=len(findings))

        # Step 6: Send final Slack report with PR link
        await run_slack_report(SlackReportInput(
            repo=repo,
            branch=branch,
            findings=findings,
            pr_url=pr_url
        ))

        logger.info("Push event processing completed successfully")

    except Exception as e:
        logger.error(f"Error processing push event: {str(e)}", exc_info=True)
        update_event_status(event_id, "error", error=str(e))

        # Try to send error notification
        try:
            await run_slack_report(SlackReportInput(
                repo=repo,
                branch=branch,
                findings=[],
                pr_url=None
            ))
        except:
            pass
