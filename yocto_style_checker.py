#!/usr/bin/env python3
"""
Yocto Recipe Style Guide Checker
Implements all rules from Yocto Project Style Guide
"""
import os
import sys
import re
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
import argparse

@dataclass
class StyleIssue:
    """Represents a style guide violation"""
    severity: str  # 'error', 'warning', 'info'
    file_path: str
    line_num: int
    rule_id: str  # e.g., '3.1', '3.4.1'
    category: str
    message: str
    suggestion: str = ""
    
class YoctoStyleChecker:
    """Comprehensive Yocto Recipe Style Guide checker"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.issues: List[StyleIssue] = []
        
        # 3.5.2 Expected variable order
        self.expected_order = [
            'SUMMARY', 'DESCRIPTION', 'HOMEPAGE', 'BUGTRACKER', 'SECTION',
            'LICENSE', 'LIC_FILES_CHKSUM', 'DEPENDS', 'PROVIDES', 'PV',
            'SRC_URI', 'SRCREV', 'S', 'PACKAGECONFIG',
            'PACKAGE_ARCH', 'PACKAGES', 'FILES',
            'RDEPENDS', 'RRECOMMENDS', 'RSUGGESTS', 'RPROVIDES', 'RCONFLICTS',
            'BBCLASSEXTEND'
        ]
        
        # Common SPDX license identifiers
        self.spdx_licenses = {
            'MIT', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 
            'GPL-3.0-or-later', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
            'LGPL-3.0-only', 'LGPL-3.0-or-later', 'BSD-2-Clause', 'BSD-3-Clause',
            'Apache-2.0', 'MPL-2.0', 'CLOSED', 'UNLICENSED'
        }
        
        # Valid Upstream-Status values
        self.upstream_status_values = {
            'Pending', 'Submitted', 'Backport', 'Denied', 
            'Inactive-Upstream', 'Inappropriate'
        }
    
    def check_recipe(self, recipe_path: Path, layer_name: str) -> List[StyleIssue]:
        """Check a single recipe file against style guide"""
        issues = []
        
        try:
            content = recipe_path.read_text(errors='ignore')
            lines = content.split('\n')
            rel_path = f"{layer_name}/{recipe_path.relative_to(self.project_root / layer_name)}"
            
            # 3.1 Recipe Naming Conventions
            issues.extend(self.check_naming_conventions(recipe_path, rel_path))
            
            # 3.2 Version Policy
            issues.extend(self.check_version_policy(recipe_path, content, lines, rel_path))
            
            # 3.4.1 Variable Formatting
            issues.extend(self.check_variable_formatting(lines, rel_path))
            
            # 3.4.2 Python Function Formatting
            issues.extend(self.check_python_formatting(lines, rel_path))
            
            # 3.5.1 Required Variables
            issues.extend(self.check_required_variables(content, lines, rel_path, recipe_path))
            
            # 3.5.2 Recipe Ordering
            issues.extend(self.check_variable_order(content, lines, rel_path))
            
            # 3.5.3 License Fields
            issues.extend(self.check_license_fields(content, lines, rel_path))
            
        except Exception as e:
            print(f"⚠️  Error checking {recipe_path}: {e}")
        
        return issues
    
    def check_naming_conventions(self, recipe_path: Path, rel_path: str) -> List[StyleIssue]:
        """3.1 Recipe Naming Conventions"""
        issues = []
        
        if recipe_path.suffix not in ['.bb', '.bbappend']:
            return issues
        
        filename = recipe_path.stem
        
        # Check format: recipename_version.bb
        if recipe_path.suffix == '.bb' and '_' not in filename and filename != 'git':
            issues.append(StyleIssue(
                severity='warning',
                file_path=rel_path,
                line_num=0,
                rule_id='3.1',
                category='naming',
                message='Recipe name missing version (should be recipename_version.bb)',
                suggestion=f'Rename to {filename}_<version>.bb or {filename}_git.bb if tracking git'
            ))
        
        # Check for hyphens in version part
        if '_' in filename:
            recipe_name, version = filename.rsplit('_', 1)
            if '-' in version and version != 'git':
                issues.append(StyleIssue(
                    severity='error',
                    file_path=rel_path,
                    line_num=0,
                    rule_id='3.1',
                    category='naming',
                    message='Hyphens not allowed in version part of recipe name',
                    suggestion=f'Replace hyphens in version: {version}'
                ))
        
        return issues
    
    def check_version_policy(self, recipe_path: Path, content: str, lines: List[str], rel_path: str) -> List[StyleIssue]:
        """3.2 Version Policy"""
        issues = []
        
        # Check for PV with git but no +git suffix
        pv_match = re.search(r'^PV\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
        if pv_match:
            pv_value = pv_match.group(1)
            
            # If using AUTOREV or git revision, should have +git
            if 'AUTOREV' in content or 'SRCREV' in content:
                if '+git' not in pv_value and 'git' not in recipe_path.stem:
                    issues.append(StyleIssue(
                        severity='warning',
                        file_path=rel_path,
                        line_num=self._find_line_num(lines, r'^PV\s*='),
                        rule_id='3.2',
                        category='version',
                        message='When using git revisions, PV should include +git',
                        suggestion=f'Set PV = "{pv_value}+git" or rename recipe to _git.bb'
                    ))
        
        # Check for PR when it should be removed
        pr_match = re.search(r'^PR\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
        pv_match = re.search(r'^PV\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
        if pr_match and pv_match:
            issues.append(StyleIssue(
                severity='info',
                file_path=rel_path,
                line_num=self._find_line_num(lines, r'^PR\s*='),
                rule_id='3.2',
                category='version',
                message='PR is manually set - consider using PR Server instead',
                suggestion='Remove PR and let PR Server handle it, or verify manual PR is needed'
            ))
        
        # Check for invalid version format (e.g., 1.5rc2 instead of 1.5~rc2)
        if pv_match:
            pv_value = pv_match.group(1)
            # Check for rc/beta/alpha without tilde
            if re.search(r'\d(rc|beta|alpha)\d', pv_value, re.IGNORECASE):
                issues.append(StyleIssue(
                    severity='warning',
                    file_path=rel_path,
                    line_num=self._find_line_num(lines, r'^PV\s*='),
                    rule_id='3.2',
                    category='version',
                    message='Pre-release versions should use tilde (~) for correct sorting',
                    suggestion=f'Use ~ before pre-release: e.g., 1.5~rc2 instead of 1.5rc2'
                ))
        
        return issues
    
    def check_variable_formatting(self, lines: List[str], rel_path: str) -> List[StyleIssue]:
        """3.4.1 Variable Formatting"""
        issues = []
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments and empty lines
            if not stripped or stripped.startswith('#'):
                continue
            
            # Check for variable assignments
            var_match = re.match(r'^([A-Z_][A-Z0-9_:]*)\s*([\+:]?=|:append|:prepend|:remove)\s*(.*)$', stripped)
            if var_match:
                var_name = var_match.group(1)
                operator = var_match.group(2)
                value = var_match.group(3)
                
                # Check space around operator (only check the assignment itself, not inside strings)
                full_line = line
                # Check for VAR= (no space before =) - but only the variable assignment, not content
                if re.search(rf'{re.escape(var_name)}=', full_line) and operator == '=':
                    # Check if this is actually VAR= (no space) vs VAR = (with space)
                    # Look for the pattern "VARNAME=" without space before =
                    if re.search(rf'{re.escape(var_name)}=\s*["\']', full_line):
                        # No space before =
                        issues.append(StyleIssue(
                            severity='warning',
                            file_path=rel_path,
                            line_num=i,
                            rule_id='3.4.1',
                            category='formatting',
                            message='Missing space before = operator',
                            suggestion=f'Use: {var_name} = ... (with spaces)'
                        ))
                
                # Check space after = - but don't check inside quoted strings
                # Only check if there's no space immediately after the operator
                if operator == '=' and value and not value.startswith(' ') and not value.startswith('"') and not value.startswith("'"):
                    # No space after =
                    issues.append(StyleIssue(
                        severity='warning',
                        file_path=rel_path,
                        line_num=i,
                        rule_id='3.4.1',
                        category='formatting',
                        message='Missing space after = operator',
                        suggestion=f'Use: {var_name} = ... (with spaces)'
                    ))
                
                # Check for single quotes instead of double quotes
                if value.strip().startswith("'") and not any(x in value for x in ['${', '${']):
                    issues.append(StyleIssue(
                        severity='info',
                        file_path=rel_path,
                        line_num=i,
                        rule_id='3.4.1',
                        category='formatting',
                        message='Single quotes used instead of double quotes',
                        suggestion=f'Use double quotes: {var_name} = "..."'
                    ))
                
                # Check continuation line alignment
                if line.rstrip().endswith('\\'):
                    # Check next line
                    if i < len(lines):
                        next_line = lines[i]
                        if next_line.strip() and not re.match(r'^\s{7,}', next_line):
                            # Should be aligned
                            issues.append(StyleIssue(
                                severity='info',
                                file_path=rel_path,
                                line_num=i+1,
                                rule_id='3.4.1',
                                category='formatting',
                                message='Continuation line not properly aligned',
                                suggestion='Indent continuation lines to align with opening quote'
                            ))
            
            # Check for tabs (should use spaces)
            if '\t' in line and not stripped.startswith('#'):
                issues.append(StyleIssue(
                    severity='warning',
                    file_path=rel_path,
                    line_num=i,
                    rule_id='3.4.1',
                    category='formatting',
                    message='Tabs used instead of spaces',
                    suggestion='Use 4 spaces for indentation'
                ))
        
        return issues
    
    def check_python_formatting(self, lines: List[str], rel_path: str) -> List[StyleIssue]:
        """3.4.2 Python Function Formatting"""
        issues = []
        
        in_python = False
        python_func_line = 0
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Detect Python functions
            if stripped.startswith('python ') or stripped.startswith('def '):
                in_python = True
                python_func_line = i
                continue
            
            if in_python:
                # Check for closing brace
                if stripped == '}':
                    in_python = False
                    continue
                
                # Check indentation (should be 4 spaces)
                if line and not line.startswith(' ') and not stripped.startswith('#'):
                    # Python code not indented
                    issues.append(StyleIssue(
                        severity='warning',
                        file_path=rel_path,
                        line_num=i,
                        rule_id='3.4.2',
                        category='formatting',
                        message='Python code must use 4 spaces for indentation',
                        suggestion='Indent with 4 spaces per level'
                    ))
                
                # Check for tabs in Python code
                if '\t' in line:
                    issues.append(StyleIssue(
                        severity='error',
                        file_path=rel_path,
                        line_num=i,
                        rule_id='3.4.2',
                        category='formatting',
                        message='Tabs not allowed in Python code',
                        suggestion='Use spaces only (4 spaces per indent level)'
                    ))
        
        return issues
    
    def check_required_variables(self, content: str, lines: List[str], rel_path: str, recipe_path: Path) -> List[StyleIssue]:
        """3.5.1 Required Variables"""
        issues = []
        
        # Only check .bb files (not .bbappend)
        if recipe_path.suffix != '.bb':
            return issues
        
        # Skip image recipes - they have different requirements
        if '/recipes-core/images/' in rel_path or '/recipes-*/images/' in rel_path:
            return issues
        
        # Skip packagegroup recipes - they have different requirements
        if 'packagegroup' in recipe_path.name or 'inherit packagegroup' in content:
            return issues
        
        required_vars = {
            'SUMMARY': ('error', 'One line description of the project'),
            'DESCRIPTION': ('warning', 'defaults to SUMMARY.'),
        }
        
        for var_name, (severity, description) in required_vars.items():
            if not re.search(rf'^{var_name}\s*[?:]?=', content, re.MULTILINE):
                issues.append(StyleIssue(
                    severity=severity,
                    file_path=rel_path,
                    line_num=0,
                    rule_id='3.5.1',
                    category='metadata',
                    message=f'Missing required variable: {var_name}',
                    suggestion=f'Add: {var_name} = "{description}"'
                ))
        
        return issues
    
    def check_variable_order(self, content: str, lines: List[str], rel_path: str) -> List[StyleIssue]:
        """3.5.2 Recipe Ordering"""
        issues = []
        
        # Extract variable positions
        var_positions = {}
        inherit_line = None
        task_lines = []
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Check for variables in expected order
            for var in self.expected_order:
                if re.match(rf'^{var}\s*[?:]?=', stripped):
                    if var not in var_positions:
                        var_positions[var] = i
            
            # Check for inherit
            if stripped.startswith('inherit '):
                inherit_line = i
            
            # Check for task definitions
            if re.match(r'^(python\s+)?do_\w+\s*\(', stripped):
                task_lines.append((i, stripped))
        
        # Check order of present variables
        if len(var_positions) > 1:
            present_vars = [v for v in self.expected_order if v in var_positions]
            actual_order = sorted(present_vars, key=lambda v: var_positions[v])
            
            if present_vars != actual_order:
                wrong_vars = []
                for i, var in enumerate(actual_order):
                    if i < len(present_vars) and var != present_vars[i]:
                        wrong_vars.append(var)
                
                if wrong_vars:
                    issues.append(StyleIssue(
                        severity='info',
                        file_path=rel_path,
                        line_num=0,
                        rule_id='3.5.2',
                        category='ordering',
                        message=f'Variables not in recommended order',
                        suggestion=f'Expected order: {", ".join(present_vars)}\nActual: {", ".join(actual_order)}'
                    ))
        
        # Check inherit position (should be after S)
        if inherit_line and 'S' in var_positions:
            if inherit_line < var_positions['S']:
                issues.append(StyleIssue(
                    severity='info',
                    file_path=rel_path,
                    line_num=inherit_line,
                    rule_id='3.5.2',
                    category='ordering',
                    message='inherit should come after S variable',
                    suggestion='Move inherit statement after S = ...'
                ))
        
        # Check task ordering
        expected_task_order = [
            'do_fetch', 'do_unpack', 'do_patch', 'do_prepare_recipe_sysroot',
            'do_configure', 'do_compile', 'do_install', 'do_populate_sysroot', 'do_package'
        ]
        
        if len(task_lines) > 1:
            task_names = []
            for line_num, line_text in task_lines:
                match = re.search(r'do_(\w+)', line_text)
                if match:
                    task_names.append(match.group(0))
            
            # Check if tasks are in expected order
            ordered_tasks = [t for t in expected_task_order if t in task_names]
            actual_task_order = [t for t in task_names if t in expected_task_order]
            
            if ordered_tasks != actual_task_order:
                issues.append(StyleIssue(
                    severity='info',
                    file_path=rel_path,
                    line_num=task_lines[0][0],
                    rule_id='3.5.2',
                    category='ordering',
                    message='Tasks not in recommended execution order',
                    suggestion=f'Expected: {", ".join(ordered_tasks)}'
                ))
        
        return issues
    
    def check_license_fields(self, content: str, lines: List[str], rel_path: str) -> List[StyleIssue]:
        """3.5.3 Recipe License Fields"""
        issues = []
        
        # Skip license checks for .bbappend files - they inherit from base recipe
        if rel_path.endswith('.bbappend'):
            return issues
        
        # Skip license checks for image recipes - they aggregate packages
        if '/recipes-core/images/' in rel_path or '/recipes-*/images/' in rel_path:
            # Image recipes don't need their own license
            return issues
        
        # Check LICENSE
        license_match = re.search(r'^LICENSE\s*[?:]?=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
        if not license_match:
            issues.append(StyleIssue(
                severity='error',
                file_path=rel_path,
                line_num=0,
                rule_id='3.5.3',
                category='license',
                message='Missing LICENSE variable',
                suggestion='Add: LICENSE = "SPDX-identifier" (e.g., "MIT", "GPL-2.0-only", "CLOSED")'
            ))
            return issues  # Can't check further without LICENSE
        
        license_value = license_match.group(1)
        
        # Check for spaces in license names
        if ' ' in license_value and '&' not in license_value and '|' not in license_value:
            issues.append(StyleIssue(
                severity='warning',
                file_path=rel_path,
                line_num=self._find_line_num(lines, r'^LICENSE\s*='),
                rule_id='3.5.3',
                category='license',
                message='LICENSE should not contain spaces (use & or | as separators)',
                suggestion='Use & for AND, | for OR: e.g., "MIT & GPL-2.0-only"'
            ))
        
        # Check for non-SPDX licenses
        license_parts = re.split(r'[&|]', license_value)
        for lic in license_parts:
            lic = lic.strip()
            if lic and lic not in self.spdx_licenses and not lic.startswith('file://'):
                issues.append(StyleIssue(
                    severity='info',
                    file_path=rel_path,
                    line_num=self._find_line_num(lines, r'^LICENSE\s*='),
                    rule_id='3.5.3',
                    category='license',
                    message=f'Non-standard license identifier: {lic}',
                    suggestion='Use SPDX identifiers from meta/files/common-licenses/'
                ))
        
        # Check LIC_FILES_CHKSUM - but not required for CLOSED or packagegroups
        is_closed = 'CLOSED' in license_value or 'UNLICENSED' in license_value
        is_packagegroup = 'packagegroup' in rel_path or 'inherit packagegroup' in content
        
        if not is_closed and not is_packagegroup:
            if not re.search(r'^LIC_FILES_CHKSUM\s*[?:]?=', content, re.MULTILINE):
                issues.append(StyleIssue(
                    severity='error',
                    file_path=rel_path,
                    line_num=0,
                    rule_id='3.5.3',
                    category='license',
                    message='Missing LIC_FILES_CHKSUM variable',
                    suggestion='Add: LIC_FILES_CHKSUM = "file://COPYING;md5=..." (not needed for LICENSE="CLOSED")'
                ))
            else:
                # Check format
                chksum_match = re.search(r'LIC_FILES_CHKSUM\s*[?:]?=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
                if chksum_match:
                    chksum = chksum_match.group(1)
                    if 'file://' not in chksum or 'md5=' not in chksum:
                        issues.append(StyleIssue(
                            severity='warning',
                            file_path=rel_path,
                            line_num=self._find_line_num(lines, r'^LIC_FILES_CHKSUM'),
                            rule_id='3.5.3',
                            category='license',
                            message='LIC_FILES_CHKSUM format may be incorrect',
                            suggestion='Format: file://COPYING;md5=checksum'
                        ))
        
        return issues
    
    def check_patch_files(self, patch_path: Path, layer_name: str) -> List[StyleIssue]:
        """3.6 Patch Upstream Status"""
        issues = []
        
        try:
            content = patch_path.read_text(errors='ignore')
            rel_path = f"{layer_name}/{patch_path.relative_to(self.project_root / layer_name)}"
            
            # Check for Upstream-Status tag
            if 'Upstream-Status:' not in content:
                issues.append(StyleIssue(
                    severity='error',
                    file_path=rel_path,
                    line_num=0,
                    rule_id='3.6',
                    category='patch',
                    message='Missing Upstream-Status tag in patch',
                    suggestion='Add: Upstream-Status: Pending|Submitted|Backport|Denied|Inactive-Upstream|Inappropriate'
                ))
            else:
                # Check for valid status value
                status_match = re.search(r'Upstream-Status:\s*(\S+)', content)
                if status_match:
                    status = status_match.group(1)
                    # Extract base status (before [ ])
                    base_status = status.split('[')[0].strip()
                    
                    if base_status not in self.upstream_status_values:
                        issues.append(StyleIssue(
                            severity='warning',
                            file_path=rel_path,
                            line_num=self._find_line_in_content(content, 'Upstream-Status:'),
                            rule_id='3.6',
                            category='patch',
                            message=f'Invalid Upstream-Status value: {status}',
                            suggestion=f'Use one of: {", ".join(self.upstream_status_values)}'
                        ))
                    
                    # Check for additional info when required
                    if base_status == 'Submitted' and '[' not in status:
                        issues.append(StyleIssue(
                            severity='info',
                            file_path=rel_path,
                            line_num=self._find_line_in_content(content, 'Upstream-Status:'),
                            rule_id='3.6',
                            category='patch',
                            message='Submitted status should include where it was submitted',
                            suggestion='Use: Upstream-Status: Submitted [mailing-list or maintainer]'
                        ))
                    
                    if base_status == 'Backport' and '[' not in status:
                        issues.append(StyleIssue(
                            severity='info',
                            file_path=rel_path,
                            line_num=self._find_line_in_content(content, 'Upstream-Status:'),
                            rule_id='3.6',
                            category='patch',
                            message='Backport status should include version info',
                            suggestion='Use: Upstream-Status: Backport [commit-id or version]'
                        ))
                    
                    if base_status == 'Inappropriate' and '[' not in status:
                        issues.append(StyleIssue(
                            severity='warning',
                            file_path=rel_path,
                            line_num=self._find_line_in_content(content, 'Upstream-Status:'),
                            rule_id='3.6',
                            category='patch',
                            message='Inappropriate status must include reason',
                            suggestion='Use: Upstream-Status: Inappropriate [oe specific] or [upstream ticket <link>]'
                        ))
            
            # Check for Signed-off-by
            if 'Signed-off-by:' not in content:
                issues.append(StyleIssue(
                    severity='info',
                    file_path=rel_path,
                    line_num=0,
                    rule_id='3.6',
                    category='patch',
                    message='Missing Signed-off-by tag',
                    suggestion='Add: Signed-off-by: Your Name <your.email@example.com>'
                ))
            
        except Exception as e:
            print(f"⚠️  Error checking patch {patch_path}: {e}")
        
        return issues
    
    def check_cve_patches(self, patch_path: Path, layer_name: str) -> List[StyleIssue]:
        """3.7 CVE Patches"""
        issues = []
        
        try:
            content = patch_path.read_text(errors='ignore')
            filename = patch_path.name.lower()
            rel_path = f"{layer_name}/{patch_path.relative_to(self.project_root / layer_name)}"
            
            # Check if filename or content mentions CVE
            has_cve_in_filename = 'cve-' in filename
            has_cve_in_content = re.search(r'CVE-\d{4}-\d{4,}', content, re.IGNORECASE)
            
            if has_cve_in_filename or has_cve_in_content:
                # Should have CVE: tag
                cve_tag_match = re.search(r'^CVE:\s*(.+)$', content, re.MULTILINE)
                if not cve_tag_match:
                    issues.append(StyleIssue(
                        severity='error',
                        file_path=rel_path,
                        line_num=0,
                        rule_id='3.7',
                        category='cve',
                        message='Patch fixes CVE but missing CVE: tag',
                        suggestion='Add: CVE: CVE-YYYY-NNNN (or multiple CVEs separated by spaces)'
                    ))
                else:
                    # Validate CVE format
                    cve_list = cve_tag_match.group(1).strip()
                    cves = cve_list.split()
                    for cve in cves:
                        if not re.match(r'CVE-\d{4}-\d{4,}', cve, re.IGNORECASE):
                            issues.append(StyleIssue(
                                severity='warning',
                                file_path=rel_path,
                                line_num=self._find_line_in_content(content, 'CVE:'),
                                rule_id='3.7',
                                category='cve',
                                message=f'Invalid CVE format: {cve}',
                                suggestion='Use format: CVE-YYYY-NNNN'
                            ))
        
        except Exception as e:
            print(f"⚠️  Error checking CVE patch {patch_path}: {e}")
        
        return issues
    
    def _find_line_num(self, lines: List[str], pattern: str) -> int:
        """Find line number matching pattern"""
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line.strip()):
                return i
        return 0
    
    def _find_line_in_content(self, content: str, search_str: str) -> int:
        """Find line number containing string in content"""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if search_str in line:
                return i
        return 0

def analyze_layers(project_path: str, layer_names: List[str]):
    """Analyze layers for style guide compliance"""
    
    project_path = Path(project_path).resolve()
    
    print("="*80)
    print("YOCTO RECIPE STYLE GUIDE CHECKER")
    print("="*80)
    print(f"📁 Project: {project_path}")
    print(f"📦 Layers: {', '.join(layer_names)}")
    
    checker = YoctoStyleChecker(project_path)
    all_issues = []
    
    for layer_name in layer_names:
        layer_path = project_path / layer_name
        if not layer_path.exists():
            print(f"❌ Layer not found: {layer_name}")
            continue
        
        print(f"\n🔍 Checking {layer_name}...")
        
        # Check recipes (.bb files)
        for recipe in layer_path.rglob('*.bb'):
            issues = checker.check_recipe(recipe, layer_name)
            all_issues.extend(issues)
        
        # Check bbappend files
        for recipe in layer_path.rglob('*.bbappend'):
            issues = checker.check_recipe(recipe, layer_name)
            all_issues.extend(issues)
        
        # Check patch files
        for patch in layer_path.rglob('*.patch'):
            issues = checker.check_patch_files(patch, layer_name)
            all_issues.extend(issues)
            issues = checker.check_cve_patches(patch, layer_name)
            all_issues.extend(issues)
    
    # Print results
    print("\n" + "="*80)
    print("STYLE GUIDE VIOLATIONS")
    print("="*80)
    
    if not all_issues:
        print("✅ No style guide violations found!")
        return
    
    # Group by rule
    by_rule = {}
    for issue in all_issues:
        if issue.rule_id not in by_rule:
            by_rule[issue.rule_id] = []
        by_rule[issue.rule_id].append(issue)
    
    # Print by rule
    for rule_id in sorted(by_rule.keys()):
        issues = by_rule[rule_id]
        print(f"\n📋 Rule {rule_id}: {issues[0].category.upper()}")
        print("-" * 80)
        
        for issue in issues:
            severity_icon = {'error': '❌', 'warning': '⚠️ ', 'info': '💡'}[issue.severity]
            line_info = f":{issue.line_num}" if issue.line_num > 0 else ""
            print(f"{severity_icon} {issue.file_path}{line_info}")
            print(f"   {issue.message}")
            if issue.suggestion:
                print(f"   💡 {issue.suggestion}")
            print()
    
    # Summary
    errors = len([i for i in all_issues if i.severity == 'error'])
    warnings = len([i for i in all_issues if i.severity == 'warning'])
    info = len([i for i in all_issues if i.severity == 'info'])
    
    print("="*80)
    print("📊 SUMMARY")
    print("="*80)
    print(f"❌ Errors: {errors}")
    print(f"⚠️  Warnings: {warnings}")
    print(f"💡 Info: {info}")
    print(f"📝 Total: {len(all_issues)}")
    
    # Save report
    output_file = f"style_guide_report_{'_'.join(layer_names[:3])}.txt"
    with open(output_file, 'w') as f:
        f.write("="*80 + "\n")
        f.write("YOCTO RECIPE STYLE GUIDE REPORT\n")
        f.write("="*80 + "\n\n")
        f.write(f"Layers: {', '.join(layer_names)}\n\n")
        
        for rule_id in sorted(by_rule.keys()):
            f.write(f"\nRule {rule_id}: {by_rule[rule_id][0].category.upper()}\n")
            f.write("-" * 80 + "\n")
            for issue in by_rule[rule_id]:
                f.write(f"{issue.severity.upper()}: {issue.file_path}:{issue.line_num}\n")
                f.write(f"  {issue.message}\n")
                if issue.suggestion:
                    f.write(f"  Suggestion: {issue.suggestion}\n")
                f.write("\n")
        
        f.write("\n" + "="*80 + "\n")
        f.write("SUMMARY\n")
        f.write("="*80 + "\n")
        f.write(f"Errors: {errors}\n")
        f.write(f"Warnings: {warnings}\n")
        f.write(f"Info: {info}\n")
        f.write(f"Total: {len(all_issues)}\n")
    
    print(f"\n💾 Report saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Yocto Recipe Style Guide Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Checks recipes against Yocto Project Style Guide:
  3.1 Recipe Naming Conventions
  3.2 Version Policy
  3.4 Recipe Formatting
  3.5 Recipe Metadata
  3.6 Patch Upstream Status
  3.7 CVE Patches

Examples:
  %(prog)s ~/workspace/yocto_project meta-aero-bsp
  %(prog)s . meta-aero-bsp meta-aero-distro meta-aero-img
        """
    )
    parser.add_argument('project_path', help='Path to Yocto project root')
    parser.add_argument('layers', nargs='+', help='Layer names to check')
    
    args = parser.parse_args()
    
    analyze_layers(args.project_path, args.layers)

if __name__ == "__main__":
    main()