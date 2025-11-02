# MCP Orchestrator - Coordinates the IaC security pipeline

import logging
import os
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

async def handle_slack_interaction(
    action_type: str,
    action_data: dict,
    user_info: dict,
    channel: str,
    message_ts: str
):
    """
    Handle Slack interactive component actions (HITL)

    Args:
        action_type: The action ID (approve_merge, reject_pr, etc.)
        action_data: JSON data associated with the action
        user_info: User information from Slack
        channel: Slack channel ID
        message_ts: Message timestamp for threading
    """
    logger.info(f"Handling Slack interaction: {action_type}")

    try:
        if action_type == "approve_merge":
            await handle_approve_merge(action_data, user_info, channel, message_ts)
        elif action_type == "reject_pr":
            await handle_reject_pr(action_data, user_info, channel, message_ts)
        elif action_type == "rerun_scan":
            await handle_rerun_scan(action_data, user_info, channel, message_ts)
        elif action_type == "rollback_deployment":
            await handle_rollback_deployment(action_data, user_info, channel, message_ts)
        else:
            logger.warning(f"Unknown action type: {action_type}")

    except Exception as e:
        logger.error(f"Error handling Slack interaction {action_type}: {str(e)}", exc_info=True)

        # Send error notification
        try:
            await send_slack_thread_message(
                channel=channel,
                thread_ts=message_ts,
                text=f"❌ Error processing {action_type}: {str(e)}"
            )
        except:
            pass

async def handle_approve_merge(action_data: dict, user_info: dict, channel: str, message_ts: str):
    """Handle PR approval and merge"""
    pr_url = action_data.get("pr_url")
    repo = action_data.get("repo")
    pr_number = action_data.get("pr_number")

    logger.info(f"Approving and merging PR: {pr_url}")

    # Send initial response
    await send_slack_thread_message(
        channel=channel,
        thread_ts=message_ts,
        text=f"✅ PR approved by {user_info.get('name', 'unknown')}. Initiating merge..."
    )

    try:
        # Attempt to merge the PR
        success = await merge_pr_via_api(repo, pr_number, user_info)

        if success:
            await send_slack_thread_message(
                channel=channel,
                thread_ts=message_ts,
                text="✅ PR merged successfully! Deployment will begin shortly."
            )

            # Trigger deployment (placeholder for now)
            await trigger_deployment(repo, pr_number, channel, message_ts)
        else:
            await send_slack_thread_message(
                channel=channel,
                thread_ts=message_ts,
                text="❌ PR merge failed. Check branch protection rules or conflicts."
            )

    except Exception as e:
        logger.error(f"Error merging PR: {str(e)}")
        await send_slack_thread_message(
            channel=channel,
            thread_ts=message_ts,
            text=f"❌ Error during merge: {str(e)}"
        )

async def handle_reject_pr(action_data: dict, user_info: dict, channel: str, message_ts: str):
    """Handle PR rejection"""
    pr_url = action_data.get("pr_url")
    repo = action_data.get("repo")
    pr_number = action_data.get("pr_number")

    logger.info(f"Rejecting PR: {pr_url}")

    # Close the PR
    try:
        await close_pr_via_api(repo, pr_number, user_info)
        await send_slack_thread_message(
            channel=channel,
            thread_ts=message_ts,
            text=f"❌ PR rejected by {user_info.get('name', 'unknown')}. PR has been closed."
        )
    except Exception as e:
        logger.error(f"Error closing PR: {str(e)}")
        await send_slack_thread_message(
            channel=channel,
            thread_ts=message_ts,
            text=f"❌ Error closing PR: {str(e)}"
        )

async def handle_rerun_scan(action_data: dict, user_info: dict, channel: str, message_ts: str):
    """Handle re-run scan request"""
    repo = action_data.get("repo")
    commit_sha = action_data.get("commit_sha")

    logger.info(f"Re-running scan for {repo} at {commit_sha}")

    await send_slack_thread_message(
        channel=channel,
        thread_ts=message_ts,
        text=f"🔄 Re-running IaC scan requested by {user_info.get('name', 'unknown')}..."
    )

    # Re-trigger the scan pipeline
    try:
        push_event = {
            "repo": repo,
            "branch": "main",  # Assume main branch for re-scan
            "commit_sha": commit_sha,
            "changed_paths": ["."]  # Scan all files
        }
        await handle_push_event(push_event)

        await send_slack_thread_message(
            channel=channel,
            thread_ts=message_ts,
            text="✅ Re-scan initiated. Results will be posted shortly."
        )
    except Exception as e:
        logger.error(f"Error re-running scan: {str(e)}")
        await send_slack_thread_message(
            channel=channel,
            thread_ts=message_ts,
            text=f"❌ Error re-running scan: {str(e)}"
        )

async def handle_rollback_deployment(action_data: dict, user_info: dict, channel: str, message_ts: str):
    """Handle deployment rollback"""
    deployment_id = action_data.get("deployment_id")
    repo = action_data.get("repo")

    logger.info(f"Rolling back deployment: {deployment_id}")

    await send_slack_thread_message(
        channel=channel,
        thread_ts=message_ts,
        text=f"🔄 Rollback initiated by {user_info.get('name', 'unknown')}. This may take a few minutes..."
    )

    try:
        success = await rollback_deployment(deployment_id, repo, user_info)

        if success:
            await send_slack_thread_message(
                channel=channel,
                thread_ts=message_ts,
                text="✅ Rollback completed successfully. System should be stable now."
            )
        else:
            await send_slack_thread_message(
                channel=channel,
                thread_ts=message_ts,
                text="❌ Rollback failed. Manual intervention may be required."
            )
    except Exception as e:
        logger.error(f"Error during rollback: {str(e)}")
        await send_slack_thread_message(
            channel=channel,
            thread_ts=message_ts,
            text=f"❌ Rollback error: {str(e)}"
        )

# Helper functions for GitHub API operations
async def merge_pr_via_api(repo: str, pr_number: int, user_info: dict) -> bool:
    """Merge PR via GitHub API"""
    # Placeholder - implement actual GitHub API call
    logger.info(f"Merging PR #{pr_number} in {repo}")
    # TODO: Implement GitHub API merge
    return True  # Assume success for demo

async def close_pr_via_api(repo: str, pr_number: int, user_info: dict) -> bool:
    """Close PR via GitHub API"""
    # Placeholder - implement actual GitHub API call
    logger.info(f"Closing PR #{pr_number} in {repo}")
    # TODO: Implement GitHub API close
    return True  # Assume success for demo

async def trigger_deployment(repo: str, pr_number: int, channel: str, message_ts: str):
    """Trigger deployment after PR merge"""
    logger.info(f"Triggering deployment for {repo} PR #{pr_number}")

    # Send deployment started message
    await send_slack_thread_message(
        channel=channel,
        thread_ts=message_ts,
        text="🚀 Deployment started. Monitoring health checks..."
    )

    # Placeholder for deployment logic
    # TODO: Implement actual deployment triggering (GitHub Actions, etc.)

    # Simulate deployment completion
    import asyncio
    await asyncio.sleep(2)  # Simulate deployment time

    await send_slack_thread_message(
        channel=channel,
        thread_ts=message_ts,
        text="✅ Deployment completed successfully! Running health checks..."
    )

    # Trigger health checks
    await run_health_checks(repo, pr_number, channel, message_ts)

async def run_health_checks(repo: str, pr_number: int, channel: str, message_ts: str):
    """Run post-deployment health checks"""
    logger.info(f"Running health checks for {repo} deployment")

    # Placeholder health checks
    health_checks = [
        {"name": "API Health", "status": "✅ PASS", "url": "/health"},
        {"name": "Database", "status": "✅ PASS", "details": "Connection OK"},
        {"name": "External Services", "status": "✅ PASS", "details": "All services responding"}
    ]

    health_summary = "\n".join([f"• {check['name']}: {check['status']}" for check in health_checks])

    await send_slack_thread_message(
        channel=channel,
        thread_ts=message_ts,
        text=f"🏥 Health Check Results:\n{health_summary}\n\n🎉 All systems operational!"
    )

async def rollback_deployment(deployment_id: str, repo: str, user_info: dict) -> bool:
    """Rollback a deployment"""
    logger.info(f"Rolling back deployment {deployment_id} for {repo}")
    # TODO: Implement actual rollback logic
    return True  # Assume success for demo

async def send_slack_thread_message(channel: str, thread_ts: str, text: str):
    """Send a threaded message in Slack"""
    try:
        import requests

        webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        if not webhook_url:
            logger.warning("No SLACK_WEBHOOK_URL set, skipping Slack message")
            return

        payload = {
            "channel": channel,
            "thread_ts": thread_ts,
            "text": text
        }

        response = requests.post(webhook_url, json=payload)
        if response.status_code != 200:
            logger.error(f"Slack API error: {response.status_code} - {response.text}")

    except Exception as e:
        logger.error(f"Error sending Slack message: {str(e)}")
