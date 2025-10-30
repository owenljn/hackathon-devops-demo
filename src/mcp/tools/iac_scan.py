# IaC Scanning Tool

import os
import json
import subprocess
import time
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any

from ..schemas import (
    IACScanInput, IACScanResponse, ScanResult, Finding,
    Severity, CheckType
)

logger = logging.getLogger(__name__)

def scan_with_checkov(directory: str, patterns: List[str]) -> Optional[ScanResult]:
    """
    Attempt to scan using Checkov if available

    Args:
        directory: Directory to scan
        patterns: File patterns to filter

    Returns:
        ScanResult if successful, None if Checkov not available
    """
    try:
        # Check if checkov is available
        subprocess.run(['checkov', '--version'], capture_output=True, check=True)
        logger.info("Using Checkov for IaC scanning")
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.info("Checkov not available, skipping real scan")
        return None

    try:
        # Run Checkov scan
        start_time = time.time()

        cmd = [
            'checkov',
            '--directory', directory,
            '--framework', 'terraform',
            '--output', 'json',
            '--quiet'
        ]

        # Add file patterns
        for pattern in patterns:
            if pattern.startswith('*.'):
                framework = pattern.split('.')[-1]
                if framework in ['tf', 'bicep', 'yaml', 'yml', 'json']:
                    cmd.extend(['--framework', framework])

        result = subprocess.run(cmd, capture_output=True, text=True)

        scan_duration = time.time() - start_time

        if result.returncode == 0:
            # Parse JSON output
            try:
                output_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.warning("Checkov output is not valid JSON")
                return None

            # Parse findings
            findings = []
            scanned_files = []

            # Checkov typically outputs results in different formats
            # This is a simplified parsing - may need adjustment based on actual Checkov output
            if 'results' in output_data:
                results = output_data['results']

                # Extract failed checks
                failed_checks = results.get('failed_checks', [])

                for check in failed_checks:
                    finding = Finding(
                        rule_id=check.get('check_id', 'unknown'),
                        check_name=check.get('check_name', check.get('check_id', 'Unknown Check')),
                        severity=_map_checkov_severity(check.get('severity', 'medium')),
                        check_type=CheckType.TERRAFORM,
                        file_path=check.get('file_path', ''),
                        line_number=check.get('line_number'),
                        code=check.get('code_block', [''])[0] if check.get('code_block') else '',
                        description=check.get('description', 'Security issue detected'),
                        remediation=check.get('remediation', None)
                    )
                    findings.append(finding)

                # Collect scanned files
                if 'passed_checks' in results:
                    scanned_files = list(set([
                        check.get('file_path', '')
                        for check in results['passed_checks'] + failed_checks
                        if check.get('file_path')
                    ]))

            return ScanResult(
                total_findings=len(findings),
                findings=findings,
                scan_duration=scan_duration,
                scanned_files=scanned_files
            )

        else:
            logger.warning(f"Checkov scan failed with return code {result.returncode}: {result.stderr}")
            return None

    except Exception as e:
        logger.error(f"Error running Checkov: {str(e)}")
        return None

def generate_mock_findings(directory: str) -> ScanResult:
    """
    Generate mock findings for demo purposes

    This creates deterministic findings based on known files
    """
    start_time = time.time()

    findings = []
    scanned_files = []

    # Look for our demo file
    demo_file = Path(directory) / "samples" / "iac" / "insecure" / "main.tf"
    if demo_file.exists():
        scanned_files.append(str(demo_file))

        # Read the file content
        try:
            with open(demo_file, 'r') as f:
                content = f.read()
        except:
            content = ""

        # Generate mock findings based on known issues in the file
        if "0.0.0.0/0" in content:
            findings.append(Finding(
                rule_id="CKV_AWS_1",
                check_name="Ensure no security groups allow ingress from 0.0.0.0/0",
                severity=Severity.HIGH,
                check_type=CheckType.TERRAFORM,
                file_path=str(demo_file),
                line_number=10,  # Approximate line
                code='cidr_blocks = ["0.0.0.0/0"]',
                description="Security group allows unrestricted inbound access from the internet",
                remediation="Replace 0.0.0.0/0 with specific IP ranges or remove the rule if not needed"
            ))

        if "tags =" not in content:
            findings.append(Finding(
                rule_id="CKV_AWS_6",
                check_name="Ensure all resources have tags",
                severity=Severity.LOW,
                check_type=CheckType.TERRAFORM,
                file_path=str(demo_file),
                line_number=None,
                code="",  # No specific code
                description="Resource is missing mandatory tags",
                remediation="Add required tags such as Environment, Project, etc."
            ))

        # Mock S3 bucket encryption finding
        if "aws_s3_bucket" in content and "server_side_encryption_configuration" not in content:
            findings.append(Finding(
                rule_id="CKV_AWS_18",
                check_name="Ensure S3 bucket has server side encryption enabled",
                severity=Severity.MEDIUM,
                check_type=CheckType.TERRAFORM,
                file_path=str(demo_file),
                line_number=None,
                code="resource \"aws_s3_bucket\"",
                description="S3 bucket does not have server-side encryption enabled",
                remediation="Add server_side_encryption_configuration block to enable encryption"
            ))

    scan_duration = time.time() - start_time

    return ScanResult(
        total_findings=len(findings),
        findings=findings,
        scan_duration=scan_duration,
        scanned_files=scanned_files
    )

def _map_checkov_severity(severity_str: str) -> Severity:
    """Map Checkov severity strings to our enum"""
    severity_map = {
        'critical': Severity.CRITICAL,
        'high': Severity.HIGH,
        'medium': Severity.MEDIUM,
        'low': Severity.LOW,
        'info': Severity.LOW
    }
    return severity_map.get(severity_str.lower(), Severity.MEDIUM)

async def run_iac_scan(scan_input: IACScanInput) -> IACScanResponse:
    """
    Main IaC scanning function

    Tries Checkov first, falls back to mock results
    """
    logger.info(f"Starting IaC scan in directory: {scan_input.directory}")

    # Try real Checkov scan first
    real_result = scan_with_checkov(scan_input.directory, scan_input.file_patterns)

    if real_result is not None:
        return IACScanResponse(
            success=True,
            message="Scan completed successfully using Checkov",
            scan_result=real_result
        )

    # Fall back to mock results
    logger.info("Using mock scan results")
    mock_result = generate_mock_findings(scan_input.directory)

    return IACScanResponse(
        success=True,
        message="Scan completed with mock results (Checkov not available)",
        scan_result=mock_result
    )
