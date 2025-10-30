#!/usr/bin/env python3
"""
Simple end-to-end test of the AutoMCP IaC Security Demo

This script tests the core pipeline without requiring external services
"""

import sys
import os
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

import asyncio

async def test_mcp_pipeline():
    """Test the MCP pipeline locally"""
    print("🧪 Testing AutoMCP IaC Security Demo")
    print("=" * 50)

    try:
        # Import and register tools
        from mcp.orchestrator import register_tools, handle_push_event
        register_tools()
        print("✅ MCP tools registered")

        # Test push event simulation
        test_event = {
            "repo": "test/repo",
            "branch": "main",
            "commit_sha": "abc123def",
            "changed_paths": ["samples/iac/insecure/main.tf"]
        }

        print("🚀 Processing test push event...")
        await handle_push_event(test_event)

        print("✅ Demo pipeline execution completed")
        print("\n📝 Expected results (with proper env vars):")
        print("   - IaC scan finds security issues in demo file")
        print("   - AI generates fixes for overly permissive CIDR and missing tags")
        print("   - PR created with automated patches")
        print("   - Slack notification sent (would fail without webhook URL)")

        return True

    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_mcp_pipeline())
    sys.exit(0 if success else 1)
