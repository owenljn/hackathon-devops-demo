# PR Creation Tool

import os
import json
import subprocess
import logging
from pathlib import Path
from typing import Optional

from ..schemas import PRCreateInput, PRCreateResponse, PRSpec, PatchSpec

logger = logging.getLogger(__name__)

def prepare_head_branch(head_branch: str, base_branch: str = "main") -> None:
    """
    Ensure we are on `head_branch` forked from `origin/<base_branch>`.
    Auto-stash a dirty working tree to avoid checkout failures.
    """
    subprocess.run(["git", "fetch", "origin", base_branch], check=True)

    # automatically stash the uncommitted works
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True, text=True, check=True
    )
    if status.stdout.strip():
        subprocess.run(["git", "stash", "--include-untracked", "-m", "automcp-prep"], check=True)

    # Create/reset head branch based on remote main branch
    subprocess.run(["git", "checkout", "-B", head_branch, f"origin/{base_branch}"], check=True)

    try:
        subprocess.run(["git", "config", "user.name"], capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email"], capture_output=True, check=True)
    except subprocess.CalledProcessError:
        subprocess.run(["git", "config", "user.name", "AutoMCP Bot"], check=True)
        subprocess.run(["git", "config", "user.email", "bot@automcp.dev"], check=True)


def apply_patches_to_directory(patches: list[PatchSpec], base_directory: str) -> bool:
    """
    Apply patches to files in the working directory

    For MVP, we do simple file overwrites when new_content is provided
    """
    try:
        for patch in patches:
            file_path = Path(patch.file_path)

            if not file_path.is_absolute():
                file_path = Path(base_directory) / file_path

            # Ensure directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # For MVP, if new_content is provided, overwrite the file
            if patch.new_content is not None:
                with open(file_path, 'w') as f:
                    f.write(patch.new_content)
                logger.info(f"Applied patch to {file_path}")
            else:
                logger.warning(f"No new_content in patch for {file_path}, skipping")

        return True

    except Exception as e:
        logger.error(f"Error applying patches: {str(e)}")
        return False

def create_branch_with_gh_cli(repo: str, branch_name: str, base_branch: str = "main") -> bool:
    """Create a new branch using GitHub CLI"""
    try:
        # Check if gh CLI is available
        subprocess.run(['gh', '--version'], capture_output=True, check=True)

        # Create branch
        cmd = ['gh', 'repo', 'sync']  # This might not be the right command
        # Actually, let's try a different approach

        # First, ensure we're in a git repo
        subprocess.run(['git', 'status'], check=True, capture_output=True)

        # Create and switch to new branch
        subprocess.run(['git', 'checkout', '-b', branch_name], check=True)

        # Set up git user if not set
        try:
            subprocess.run(['git', 'config', 'user.name'], capture_output=True, check=True)
            subprocess.run(['git', 'config', 'user.email'], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            # Set default git user for demo
            subprocess.run(['git', 'config', 'user.name', 'AutoMCP Bot'], check=True)
            subprocess.run(['git', 'config', 'user.email', 'bot@automcp.dev'], check=True)

        return True

    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("GitHub CLI not available or git repo issues")
        return False

def create_pr_with_gh_cli(
    repo: str,
    title: str,
    body: str,
    head_branch: str,
    base_branch: str
) -> Optional[str]:
    """Create PR using GitHub CLI"""
    try:
        # Commit changes first
        subprocess.run(['git', 'add', '.'], check=True)
        subprocess.run(['git', 'commit', '-m', f'Automated fixes: {title}'], check=True)

        # Push branch
        subprocess.run(['git', 'push', '-u', 'origin', head_branch], check=True)

        # Create PR
        cmd = [
            'gh', 'pr', 'create',
            '--title', title,
            '--body', body,
            '--head', head_branch,
            '--base', base_branch
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        pr_url = result.stdout.strip()

        if pr_url:
            logger.info(f"Created PR: {pr_url}")
            return pr_url

    except subprocess.CalledProcessError as e:
        logger.error(f"GitHub CLI PR creation failed: {e.stderr}")

    return None

def create_pr_with_rest_api(
    repo: str,
    title: str,
    body: str,
    head_branch: str,
    base_branch: str,
    token: str
) -> Optional[str]:
    """Create PR using GitHub REST API"""
    try:
        import requests

        api_url = f"https://api.github.com/repos/{repo}/pulls"
        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }

        payload = {
            'title': title,
            'body': body,
            'head': head_branch,
            'base': base_branch,
            'draft': False
        }

        response = requests.post(api_url, json=payload, headers=headers)

        if response.status_code == 201:
            pr_data = response.json()
            pr_url = pr_data.get('html_url')
            logger.info(f"Created PR via REST API: {pr_url}")
            return pr_url
        else:
            logger.error(f"GitHub API error: {response.status_code} - {response.text}")

    except Exception as e:
        logger.error(f"REST API PR creation failed: {str(e)}")

    return None

def _git_has_changes() -> bool:
    """Return True if working tree has changes."""
    res = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True, text=True
    )
    return bool(res.stdout.strip())

def _ensure_at_least_one_change(base_dir: str, patches_count: int) -> None:
    """
    If there are no patches and no diffs, create a small report file so that
    a commit/PR can still be created (useful for demos).
    """
    if patches_count == 0 and not _git_has_changes():
        report_path = Path(base_dir) / "security_report.md"
        report_path.write_text(
            "# Automated IaC Scan\n\n"
            "- No auto-fixes were generated.\n"
            "- This PR is opened for manual review and policy exception tracking.\n",
            encoding="utf-8"
        )


async def run_pr_create(pr_input: PRCreateInput) -> PRCreateResponse:
    """Create a PR with applied patches (robust to no-diff situations)."""
    logger.info(f"Creating PR for repo {pr_input.repo}")

    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        return PRCreateResponse(
            success=False,
            message="GITHUB_TOKEN environment variable not set"
        )

    # Prepare the branch FIRST so patches/commit land on it
    try:
        prepare_head_branch(
            head_branch=pr_input.pr_spec.head_branch,
            base_branch=pr_input.pr_spec.base_branch,
        )
    except subprocess.CalledProcessError as e:
        return PRCreateResponse(success=False, message=f"Failed to prepare branch: {e}")

    # Get current working directory as base for file operations
    base_dir = os.getcwd()

    # apply the patch
    if not apply_patches_to_directory(pr_input.patches, base_dir):
        return PRCreateResponse(
            success=False,
            message="Failed to apply patches to working directory"
        )

    _ensure_at_least_one_change(base_dir, patches_count=len(pr_input.patches))

    # skip PR if no change to commit
    if not _git_has_changes():
        logger.warning("No file changes detected after patch application. Skipping PR creation.")
        return PRCreateResponse(
            success=False,
            message="No file changes to commit or push."
        )

    # use gh CLI, and failover to RESTful API
    pr_url = create_pr_with_gh_cli(
        pr_input.repo,
        pr_input.pr_spec.title,
        pr_input.pr_spec.body,
        pr_input.pr_spec.head_branch,  # eg. 'autofix/<sha>'
        pr_input.pr_spec.base_branch   # 'main' branch
    )

    if not pr_url:
        logger.info("Trying REST API fallback")
        pr_url = create_pr_with_rest_api(
            pr_input.repo,
            pr_input.pr_spec.title,
            pr_input.pr_spec.body,
            pr_input.pr_spec.head_branch,
            pr_input.pr_spec.base_branch,
            github_token
        )

    if pr_url:
        return PRCreateResponse(
            success=True,
            message="PR created successfully",
            pr_url=pr_url
        )

    return PRCreateResponse(
        success=False,
        message="Failed to create PR - check GitHub CLI authentication and repository access"
    )
