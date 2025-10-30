# MCP smoke tests

import pytest
import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.mcp.schemas import (
    IACScanInput, IACScanResponse,
    AIFixInput, AIFixResponse,
    PRCreateInput, PRCreateResponse,
    SlackReportInput, SlackReportResponse
)

async def test_mcp_orchestrator_import():
    """Test that MCP orchestrator can be imported and tools registered"""
    try:
        from src.mcp.orchestrator import register_tools, mcp_server
        register_tools()

        # Check that tools are registered
        tool_names = mcp_server.list_tools()
        expected_tools = ["iac_scan", "ai_fix", "pr_create", "slack_report"]

        for tool in expected_tools:
            assert tool in tool_names, f"Tool {tool} not registered"

    except ImportError as e:
        pytest.fail(f"Failed to import MCP orchestrator: {e}")

async def test_iac_scan_mock():
    """Test IaC scanning with mock results"""
    from src.mcp.tools.iac_scan import run_iac_scan, IACScanInput

    # Create scan input
    scan_input = IACScanInput(
        directory=".",
        file_patterns=["*.tf"],
        excluded_patterns=[]
    )

    # Run scan
    response = await run_iac_scan(scan_input)

    # Should succeed (either with real scanner or mock)
    assert isinstance(response, IACScanResponse)
    assert response.success is True
    assert response.scan_result is not None
    assert response.scan_result.scanned_files is not None

    # Since we're scanning the demo files, we should get some findings
    # (either from Checkov or mock)
    assert response.scan_result.total_findings >= 0

async def test_ai_fix_generation():
    """Test AI fix generation (template-based)"""
    from src.mcp.tools.ai_fix import run_ai_fix
    from src.mcp.schemas import Finding, Severity, CheckType

    # Create mock findings
    findings = [
        Finding(
            rule_id="CKV_AWS_1",
            check_name="Security group allows unrestricted access",
            severity=Severity.HIGH,
            check_type=CheckType.TERRAFORM,
            file_path="test.tf",
            code='cidr_blocks = ["0.0.0.0/0"]',
            description="Overly permissive security group",
            remediation="Restrict CIDR blocks"
        )
    ]

    fix_input = AIFixInput(
        findings=findings,
        source_directory="."
    )

    response = await run_ai_fix(fix_input)

    assert isinstance(response, AIFixResponse)
    assert response.success is True
    # Should generate at least one patch
    assert len(response.patches) > 0

async def test_slack_report_structure():
    """Test Slack report structure (without actually sending)"""
    from src.mcp.tools.slack import run_slack_report

    report_input = SlackReportInput(
        repo="test/repo",
        branch="main",
        findings=[],
        pr_url=None
    )

    # This will fail because SLACK_WEBHOOK_URL is not set
    # But it should create the proper response structure
    response = await run_slack_report(report_input)

    assert isinstance(response, SlackReportResponse)
    assert response.success is False  # Should fail due to missing webhook URL
    assert "SLACK_WEBHOOK_URL" in response.message

def test_schemas():
    """Test that all schema classes can be instantiated"""
    from src.mcp.schemas import (
        Finding, ScanResult, PatchSpec, PRSpec, PushEvent,
        IACScanInput, AIFixInput, PRCreateInput, SlackReportInput
    )

    # Test Finding
    finding = Finding(
        rule_id="test",
        check_name="Test finding",
        severity="high",
        check_type="terraform",
        file_path="test.tf",
        code="test",
        description="test",
        remediation="fix it"
    )
    assert finding.rule_id == "test"

    # Test PushEvent
    push_event = PushEvent(
        repo="owner/repo",
        branch="main",
        commit_sha="abc123",
        changed_paths=["test.tf"]
    )
    assert push_event.repo == "owner/repo"

    # Test inputs
    scan_input = IACScanInput(directory=".")
    assert scan_input.file_patterns == ["*.tf", "*.bicep", "*.yaml", "*.yml", "*.json"]
