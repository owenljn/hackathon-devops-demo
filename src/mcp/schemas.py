# Pydantic models for MCP tool inputs and outputs

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum

class Severity(str, Enum):
    """Security finding severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class CheckType(str, Enum):
    """Type of security check"""
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    ARM = "arm"
    KUBERNETES = "kubernetes"
    GENERAL = "general"

class Finding(BaseModel):
    """Security finding from IaC scanning"""
    rule_id: str = Field(..., description="Unique identifier for the security rule")
    check_name: str = Field(..., description="Human-readable check name")
    severity: Severity = Field(..., description="Severity level of the finding")
    check_type: CheckType = Field(..., description="Type of infrastructure check")
    file_path: str = Field(..., description="Path to the file containing the issue")
    line_number: Optional[int] = Field(None, description="Line number where the issue occurs")
    code: str = Field(..., description="The problematic code snippet")
    description: str = Field(..., description="Detailed description of the issue")
    remediation: Optional[str] = Field(None, description="Suggested fix or remediation steps")

class ScanResult(BaseModel):
    """Result from IaC scanning"""
    total_findings: int = Field(..., description="Total number of findings")
    findings: List[Finding] = Field(..., description="List of individual findings")
    scan_duration: float = Field(..., description="Time taken to complete the scan in seconds")
    scanned_files: List[str] = Field(..., description="List of files that were scanned")

class PatchOperation(BaseModel):
    """Individual patch operation"""
    op: str = Field(..., description="Operation type: 'replace', 'add', 'remove'")
    path: str = Field(..., description="JSONPath-style path to modify (for structured files)")
    value: Optional[Any] = Field(None, description="New value for replace/add operations")
    from_path: Optional[str] = Field(None, description="Source path for move operations")

class PatchSpec(BaseModel):
    """Specification for a code patch"""
    file_path: str = Field(..., description="Path to the file to patch")
    description: str = Field(..., description="Description of what this patch does")
    operations: List[PatchOperation] = Field(..., description="List of patch operations to apply")
    new_content: Optional[str] = Field(None, description="Complete new content (alternative to operations)")

class PRSpec(BaseModel):
    """Specification for creating a pull request"""
    title: str = Field(..., description="PR title")
    body: str = Field(..., description="PR description body")
    head_branch: str = Field(..., description="Source branch name")
    base_branch: str = Field("main", description="Target branch name")
    draft: bool = Field(False, description="Whether to create as draft PR")

class SlackMessageSpec(BaseModel):
    """Specification for Slack message"""
    message: Dict[str, Any] = Field(..., description="Slack Block Kit message payload")
    channel: Optional[str] = Field(None, description="Target channel override")

class PushEvent(BaseModel):
    """Normalized push event data"""
    repo: str = Field(..., description="Repository name (owner/repo)")
    branch: str = Field(..., description="Branch name")
    commit_sha: str = Field(..., description="Commit SHA")
    changed_paths: List[str] = Field(..., description="List of changed file paths")

# Tool Input Models

class IACScanInput(BaseModel):
    """Input for IaC scanning tool"""
    directory: str = Field(".", description="Directory to scan for IaC files")
    file_patterns: List[str] = Field(["*.tf", "*.bicep", "*.yaml", "*.yml", "*.json"], description="File patterns to scan")
    excluded_patterns: List[str] = Field([], description="Patterns to exclude from scanning")

class AIFixInput(BaseModel):
    """Input for AI fix generation tool"""
    findings: List[Finding] = Field(..., description="Security findings to generate fixes for")
    source_directory: str = Field(".", description="Source directory containing IaC files")

class PRCreateInput(BaseModel):
    """Input for PR creation tool"""
    repo: str = Field(..., description="Target repository (owner/repo)")
    branch_name: str = Field(..., description="Name for the new branch")
    patches: List[PatchSpec] = Field(..., description="Patches to apply")
    pr_spec: PRSpec = Field(..., description="PR specification")

class SlackReportInput(BaseModel):
    """Input for Slack reporting tool"""
    repo: str = Field(..., description="Repository name")
    branch: str = Field(..., description="Branch name")
    findings: List[Finding] = Field(..., description="Security findings")
    pr_url: Optional[str] = Field(None, description="PR URL if created")

# Tool Response Models

class ToolResponse(BaseModel):
    """Base response model for tools"""
    success: bool = Field(..., description="Whether the operation succeeded")
    message: str = Field(..., description="Human-readable status message")
    data: Optional[Dict[str, Any]] = Field(None, description="Additional response data")

class IACScanResponse(ToolResponse):
    """Response from IaC scanning tool"""
    scan_result: Optional[ScanResult] = Field(None, description="Scan results if successful")

class AIFixResponse(ToolResponse):
    """Response from AI fix generation tool"""
    patches: List[PatchSpec] = Field([], description="Generated patches")

class PRCreateResponse(ToolResponse):
    """Response from PR creation tool"""
    pr_url: Optional[str] = Field(None, description="URL of created PR")
    branch_url: Optional[str] = Field(None, description="URL of created branch")

class SlackReportResponse(ToolResponse):
    """Response from Slack reporting tool"""
    message_ts: Optional[str] = Field(None, description="Slack message timestamp if sent")
