# Slack Routes for Interactive Buttons and HITL

from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
import json
import logging
import hmac
import hashlib
import os
from typing import Dict, Any

from ..mcp.orchestrator import handle_slack_interaction

router = APIRouter()
logger = logging.getLogger(__name__)

def verify_slack_signature(payload: bytes, signature: str, timestamp: str, secret: str) -> bool:
    """Verify Slack request signature"""
    if not secret:
        return True  # Skip verification if no secret configured

    # Slack signature format: v0=timestamp.signature
    if not signature.startswith('v0='):
        return False

    sig_parts = signature.split('=')
    if len(sig_parts) != 2:
        return False

    # Create the basestring
    basestring = f"v0:{timestamp}:{payload.decode('utf-8')}"

    # Create the expected signature
    expected_signature = hmac.new(
        secret.encode(),
        basestring.encode(),
        hashlib.sha256
    ).hexdigest()

    expected_header = f"v0={expected_signature}"

    return hmac.compare_digest(expected_header, signature)

@router.post("/slack/interactive", summary="Slack Interactive Component Handler")
async def slack_interactive_handler(
    request: Request,
    background_tasks: BackgroundTasks
):
    """
    Handle Slack interactive component actions (buttons, etc.)

    This endpoint receives payloads from Slack when users click buttons
    in interactive messages (Approve & Merge, Reject, Re-run Scan, etc.)
    """

    try:
        # Get raw payload
        payload = await request.body()

        # Parse the payload (Slack sends it as form-encoded)
        form_data = await request.form()
        payload_str = form_data.get('payload')

        if not payload_str:
            raise HTTPException(status_code=400, detail="Missing payload")

        # Convert to string content
        payload_content = str(payload_str)

        try:
            slack_payload = json.loads(payload_content)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

        # Verify signature if configured
        signature = request.headers.get("X-Slack-Signature")
        timestamp = request.headers.get("X-Slack-Request-Timestamp")
        secret = os.getenv("SLACK_SIGNING_SECRET")

        if secret and not verify_slack_signature(payload, signature or "", timestamp or "", secret):
            logger.warning("Invalid Slack signature")
            raise HTTPException(status_code=401, detail="Invalid signature")

        # Extract action details
        action = slack_payload.get("actions", [{}])[0] if slack_payload.get("actions") else {}
        action_type = action.get("action_id")
        action_value = action.get("value", "{}")

        try:
            action_data = json.loads(action_value)
        except json.JSONDecodeError:
            action_data = {}

        # Extract context
        user = slack_payload.get("user", {})
        user_id = user.get("id")
        user_name = user.get("name", "unknown")

        channel = slack_payload.get("container", {}).get("channel_id")
        message_ts = slack_payload.get("container", {}).get("message_ts")

        # Log the interaction
        logger.info(f"Slack interaction: {action_type} by {user_name} ({user_id})")

        # Handle the action in background
        background_tasks.add_task(
            handle_slack_interaction,
            action_type=action_type,
            action_data=action_data,
            user_info={"id": user_id, "name": user_name},
            channel=channel,
            message_ts=message_ts
        )

        # Respond immediately to Slack (within 3 seconds)
        # For now, just acknowledge the action
        action_name = action_type.replace('_', ' ') if action_type else 'unknown'
        response_text = f"Processing {action_name} request from {user_name}..."

        return {
            "response_type": "ephemeral",  # Only visible to the user who clicked
            "text": response_text,
            "replace_original": False
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing Slack interaction: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/slack/events", summary="Slack Events Handler")
async def slack_events_handler(request: Request, background_tasks: BackgroundTasks):
    """
    Handle Slack Events API (for future use with deployment notifications)
    """
    try:
        payload = await request.json()

        # Handle URL verification challenge
        if payload.get("type") == "url_verification":
            return {"challenge": payload.get("challenge")}

        # Handle actual events
        event = payload.get("event", {})
        event_type = event.get("type")

        logger.info(f"Received Slack event: {event_type}")

        # For now, just log events
        # Future: handle deployment status updates, health check results, etc.

        return {"ok": True}

    except Exception as e:
        logger.error(f"Error processing Slack event: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/slack/test", summary="Test Slack Integration")
async def test_slack_integration():
    """Test endpoint for Slack integration setup"""
    return {
        "status": "slack_integration_ready",
        "interactive_endpoint": "/slack/interactive",
        "events_endpoint": "/slack/events",
        "supported_actions": [
            "approve_merge",
            "reject_pr",
            "rerun_scan",
            "rollback_deployment"
        ],
        "note": "Configure these endpoints in your Slack app settings"
    }
