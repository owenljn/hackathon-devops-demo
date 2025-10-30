# GitHub Webhook Routes

from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
import hmac
import hashlib
import json
import logging
from typing import List, Dict, Any
import os

from ..mcp.orchestrator import handle_push_event

router = APIRouter()
logger = logging.getLogger(__name__)

def verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature using HMAC-SHA256"""
    if not secret:
        return True  # Skip verification if no secret configured

    expected_signature = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(f"sha256={expected_signature}", signature)

@router.post("/github", summary="GitHub Push Webhook")
async def github_push_webhook(
    request: Request,
    background_tasks: BackgroundTasks
):
    """
    Handle GitHub push webhook events.

    Processes push events to detect IaC changes and trigger automated security scanning.
    """

    try:
        # Get raw payload
        payload = await request.body()

        # Verify signature if configured
        signature = request.headers.get("X-Hub-Signature-256")
        secret = os.getenv("GITHUB_WEBHOOK_SECRET")
        if not verify_github_signature(payload, signature or "", secret or ""):
            logger.warning("Invalid GitHub webhook signature")
            raise HTTPException(status_code=401, detail="Invalid signature")

        # Parse JSON payload
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

        # Only process push events
        event_type = request.headers.get("X-GitHub-Event", "")
        if event_type != "push":
            logger.info(f"Ignoring non-push event: {event_type}")
            return {"status": "ignored", "event": event_type}

        # Extract relevant push event data
        repo_full_name = data.get("repository", {}).get("full_name", "")
        ref = data.get("ref", "")
        after_commit = data.get("after", "")
        commits = data.get("commits", [])

        # Filter for IaC file changes
        iac_extensions = {'.tf', '.bicep', '.yaml', '.yml', '.json'}
        changed_files = []

        for commit in commits:
            for file_path in commit.get("modified", []) + commit.get("added", []) + commit.get("removed", []):
                if any(file_path.endswith(ext) for ext in iac_extensions):
                    changed_files.append(file_path)

        # Skip if no IaC files changed
        if not changed_files:
            logger.info("No IaC files changed in push, skipping scan")
            return {"status": "no_iac_changes", "changed_files": []}

        # Construct normalized event
        normalized_event = {
            "repo": repo_full_name,
            "branch": ref.replace("refs/heads/", "") if ref.startswith("refs/heads/") else ref,
            "commit_sha": after_commit,
            "changed_paths": changed_files
        }

        logger.info(f"Processing IaC push event: {normalized_event}")

        # Run MCP orchestrator in background to respond quickly to webhook
        background_tasks.add_task(handle_push_event, normalized_event)

        return {
            "status": "processing",
            "event_type": "push",
            "repo": repo_full_name,
            "iac_files_changed": len(changed_files),
            "message": "IaC scan initiated in background"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing GitHub webhook: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/test/github", summary="Test GitHub Webhook")
async def test_github_webhook():
    """Test endpoint to verify webhook setup"""
    return {
        "status": "webhook_endpoint_active",
        "webhook_url": "/webhook/github",
        "expected_events": ["push"],
        "supported_file_types": [".tf", ".bicep", ".yaml", ".yml", ".json"]
    }
