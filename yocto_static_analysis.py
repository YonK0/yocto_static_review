#!/usr/bin/env python3
"""
Yocto Custom Layer Analyzer v2
Combines static analysis + AI review
"""
import os
import sys
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
import argparse

@dataclass
class Issue:
    """Represents a found issue"""
    severity: str  # 'critical', 'warning', 'info'
    file_path: str
    line_num: int
    issue_type: str
    message: str
    suggestion: str = ""

class YoctoStaticAnalyzer:
    """Static analysis for common Yocto issues"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.issues: List[Issue] = []
        
        # Yocto default variables that shouldn't be redefined
        self.yocto_defaults = {
            'inherit': ['base'],  # base is inherited by default
            'S': '${WORKDIR}/${PN}-${PV}',  # Common default
        }
        
        # Expected variable order
        self.expected_order = ['SUMMARY', 'DESCRIPTION', 'HOMEPAGE', 'BUGTRACKER', 'SECTION', 'LICENSE']
    
    def analyze_recipe(self, recipe_path: Path, layer_name: str) -> List[Issue]:
        """Analyze a single .bb or .bbappend file"""
        issues = []
        
        try:
            content = recipe_path.read_text(errors='ignore')
            lines = content.split('\n')
            
            rel_path = f"{layer_name}/{recipe_path.relative_to(self.project_root / layer_name)}"
            
            # Check filename has version
            # if recipe_path.suffix == '.bb' and '_' not in recipe_path.stem:
            #     issues.append(Issue(
            #         severity='warning',
            #         file_path=rel_path,
            #         line_num=0,
            #         issue_type='naming',
            #         message='Recipe name missing version',
            #         suggestion=f'Should be {recipe_path.stem}_<version>.bb'
            #     ))
            
            # Check required fields
            has_license = False
            has_summary = False
            has_description = False
            
            # Check for AUTOREV
            # Check for absolute paths
            # Check variable order
            var_positions = {}
            
            for i, line in enumerate(lines, 1):
                line_stripped = line.strip()
                
                # Skip comments
                if line_stripped.startswith('#'):
                    continue
                
                # # Check LICENSE
                # if re.match(r'^LICENSE\s*[?:]?=', line_stripped):
                #     has_license = True
                
                # # Check SUMMARY
                # if re.match(r'^SUMMARY\s*[?:]?=', line_stripped):
                #     has_summary = True
                #     var_positions['SUMMARY'] = i
                
                # # Check DESCRIPTION
                # if re.match(r'^DESCRIPTION\s*[?:]?=', line_stripped):
                #     has_description = True
                #     var_positions['DESCRIPTION'] = i
                
                # # Check HOMEPAGE
                # if re.match(r'^HOMEPAGE\s*[?:]?=', line_stripped):
                #     var_positions['HOMEPAGE'] = i
                
                # # Check BUGTRACKER
                # if re.match(r'^BUGTRACKER\s*[?:]?=', line_stripped):
                #     var_positions['BUGTRACKER'] = i
                
                # Check SECTION
                if re.match(r'^SECTION\s*[?:]?=', line_stripped):
                    var_positions['SECTION'] = i
                
                # Check for AUTOREV
                if 'AUTOREV' in line_stripped and 'SRCREV' in line_stripped:
                    issues.append(Issue(
                        severity='critical',
                        file_path=rel_path,
                        line_num=i,
                        issue_type='autorev',
                        message='Using AUTOREV (non-reproducible builds)',
                        suggestion='Use fixed SRCREV = "<commit-hash>"'
                    ))
                
                # Check for absolute paths (should use ${S}, ${D}, ${WORKDIR})
                if 'do_install' in line_stripped or 'do_compile' in line_stripped:
                    # Look ahead for absolute paths in the function
                    func_start = i
                    func_lines = []
                    for j in range(i, min(i+20, len(lines))):
                        func_lines.append(lines[j])
                        if lines[j].strip() == '}':
                            break
                    
                    func_content = '\n'.join(func_lines)
                    # Check for absolute paths like /usr/bin, /etc (not ${D}/etc)
                    abs_path_pattern = r'(?<!\$\{[A-Z]\})/(?:usr|etc|opt|var|bin|lib)/'
                    if re.search(abs_path_pattern, func_content) and '${D}' not in func_content:
                        issues.append(Issue(
                            severity='critical',
                            file_path=rel_path,
                            line_num=func_start,
                            issue_type='absolute_path',
                            message='Using absolute paths instead of ${S}/${D}/${WORKDIR}',
                            suggestion='Use ${D}/etc instead of /etc, ${S} for source dir'
                        ))
                
                # Check for hardcoded passwords
                if re.search(r'(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', line_stripped, re.IGNORECASE):
                    if 'PASSWORD' in line_stripped or 'passwd' in line_stripped:
                        issues.append(Issue(
                            severity='critical',
                            file_path=rel_path,
                            line_num=i,
                            issue_type='security',
                            message='Hardcoded password detected',
                            suggestion='Use password hashing or external configuration'
                        ))
                
                # Check for redundant RDEPENDS (Yocto auto-handles shared libraries)
                if 'RDEPENDS' in line_stripped and 'lib' in line_stripped.lower():
                    issues.append(Issue(
                        severity='info',
                        file_path=rel_path,
                        line_num=i,
                        issue_type='rdepends',
                        message='RDEPENDS on library - Yocto auto-handles shared library dependencies',
                        suggestion='Remove unless explicit runtime dependency needed'
                    ))
            
            # # Check required fields for .bb files
            # if recipe_path.suffix == '.bb':
            #     if not has_license:
            #         issues.append(Issue(
            #             severity='critical',
            #             file_path=rel_path,
            #             line_num=0,
            #             issue_type='license',
            #             message='Missing LICENSE variable',
            #             suggestion='Add: LICENSE = "CLOSED" or appropriate license'
            #         ))
                
            #     if not has_summary:
            #         issues.append(Issue(
            #             severity='warning',
            #             file_path=rel_path,
            #             line_num=0,
            #             issue_type='metadata',
            #             message='Missing SUMMARY variable',
            #             suggestion='Add: SUMMARY = "Brief description"'
            #         ))
                
            #     if not has_description:
            #         issues.append(Issue(
            #             severity='info',
            #             file_path=rel_path,
            #             line_num=0,
            #             issue_type='metadata',
            #             message='Missing DESCRIPTION variable',
            #             suggestion='Add: DESCRIPTION = "Detailed description"'
            #         ))
            
            # Check variable ordering
            if len(var_positions) > 1:
                actual_order = sorted(var_positions.items(), key=lambda x: x[1])
                expected_vars = [v for v in self.expected_order if v in var_positions]
                actual_vars = [v[0] for v in actual_order]
                
                if actual_vars != expected_vars:
                    issues.append(Issue(
                        severity='info',
                        file_path=rel_path,
                        line_num=0,
                        issue_type='style',
                        message=f'Variable order: {" -> ".join(actual_vars)} (expected: {" -> ".join(expected_vars)})',
                        suggestion=f'Reorder to: {", ".join(expected_vars)}'
                    ))
            
        except Exception as e:
            print(f"⚠️  Error analyzing {recipe_path}: {e}")
        
        return issues
    
    def check_layer_structure(self, layer_path: Path, layer_name: str) -> List[Issue]:
        """Check if recipes are in correct layer type"""
        issues = []
        
        # BSP layers should only have hardware-specific stuff
        if 'bsp' in layer_name.lower():
            # Check for application recipes in BSP layer
            for recipe in layer_path.rglob('*.bb'):
                rel_path = recipe.relative_to(layer_path)
                
                # Apps should not be in BSP layer
                if 'recipes-core' in str(rel_path) or 'recipes-apps' in str(rel_path):
                    if not any(hw in recipe.stem for hw in ['kernel', 'bootloader', 'firmware', 'driver']):
                        issues.append(Issue(
                            severity='warning',
                            file_path=f"{layer_name}/{rel_path}",
                            line_num=0,
                            issue_type='layer_structure',
                            message='Application recipe in BSP layer',
                            suggestion='Move to meta-*-apps or meta-*-distro layer'
                        ))
        
        return issues
    
    def detect_duplicates(self, layer_paths: List[Tuple[str, Path]]) -> List[Issue]:
        """Detect duplicate recipes that should use bbclass"""
        issues = []
        
        # Collect all recipes and their do_install content
        recipes_content = {}
        
        for layer_name, layer_path in layer_paths:
            for recipe in layer_path.rglob('*.bb'):
                try:
                    content = recipe.read_text(errors='ignore')
                    # Extract do_install content
                    do_install_match = re.search(r'do_install\(\)\s*\{([^}]+)\}', content, re.DOTALL)
                    if do_install_match:
                        install_content = do_install_match.group(1).strip()
                        if install_content:
                            if install_content not in recipes_content:
                                recipes_content[install_content] = []
                            recipes_content[install_content].append((layer_name, recipe))
                except:
                    continue
        
        # Find duplicates
        for content, recipes in recipes_content.items():
            if len(recipes) >= 2 and len(content) > 100:  # Significant duplication
                recipe_list = ', '.join([f"{ln}/{r.name}" for ln, r in recipes])
                issues.append(Issue(
                    severity='info',
                    file_path=recipe_list,
                    line_num=0,
                    issue_type='duplication',
                    message=f'Duplicate do_install code in {len(recipes)} recipes',
                    suggestion='Consider creating a bbclass to share common installation logic'
                ))
        
        return issues

def analyze_custom_layers(project_path: str, layer_names: List[str]):
    """
    Analyze specific custom meta-layers with static + AI analysis
    """
    
    project_path = Path(project_path).resolve()
    
    print(f"🔍 Analyzing custom layers in: {project_path}")
    print(f"📁 Layers: {', '.join(layer_names)}")
    
    # Verify layers exist
    valid_layers = []
    layer_paths = []
    for layer_name in layer_names:
        layer_path = project_path / layer_name
        if layer_path.exists() and layer_path.is_dir():
            valid_layers.append(layer_name)
            layer_paths.append((layer_name, layer_path))
            print(f"✅ Found: {layer_name}")
        else:
            print(f"❌ Missing: {layer_name}")
    
    if not valid_layers:
        print("❌ No valid layers found!")
        return
    
    # Phase 1: Static Analysis
    print("\n" + "="*80)
    print("YOCTO STATIC ANALYSIS")
    print("="*80)
    
    analyzer = YoctoStaticAnalyzer(project_path)
    all_static_issues = []
    
    for layer_name, layer_path in layer_paths:
        print(f"\n📦 Analyzing {layer_name}...")
        
        # Analyze recipes
        for recipe in layer_path.rglob('*.bb'):
            issues = analyzer.analyze_recipe(recipe, layer_name)
            all_static_issues.extend(issues)
        
        for recipe in layer_path.rglob('*.bbappend'):
            issues = analyzer.analyze_recipe(recipe, layer_name)
            all_static_issues.extend(issues)
        
        # Check layer structure
        structure_issues = analyzer.check_layer_structure(layer_path, layer_name)
        all_static_issues.extend(structure_issues)
    
    # Check for duplicates across layers
    dup_issues = analyzer.detect_duplicates(layer_paths)
    all_static_issues.extend(dup_issues)
    
    # Print static analysis results
    print_issues(all_static_issues, "STATIC ANALYSIS")
    
def print_issues(issues: List[Issue], title: str):
    """Pretty print issues grouped by file"""
    if not issues:
        print("✅ No issues found!")
        return
    
    # Group by file
    by_file = {}
    for issue in issues:
        if issue.file_path not in by_file:
            by_file[issue.file_path] = []
        by_file[issue.file_path].append(issue)
    
    severity_icons = {
        'critical': '❌',
        'warning': '⚠️ ',
        'info': '💡'
    }
    
    for file_path, file_issues in sorted(by_file.items()):
        print(f"\n📁 {file_path}")
        for issue in file_issues:
            icon = severity_icons.get(issue.severity, '•')
            line_info = f":{issue.line_num}" if issue.line_num > 0 else ""
            print(f"  {icon} {issue.message}")
            if issue.suggestion:
                print(f"     💡 {issue.suggestion}")

def generate_report(static_issues: List[Issue], ai_output: str, layers: List[str]) -> str:
    """Generate combined report"""
    report = "="*80 + "\n"
    report += "YOCTO CUSTOM LAYER REVIEW REPORT\n"
    report += "="*80 + "\n\n"
    report += f"Layers analyzed: {', '.join(layers)}\n\n"
    
    report += "="*80 + "\n"
    report += "STATIC ANALYSIS RESULTS\n"
    report += "="*80 + "\n"
    
    # Group static issues by severity
    critical = [i for i in static_issues if i.severity == 'critical']
    warnings = [i for i in static_issues if i.severity == 'warning']
    info = [i for i in static_issues if i.severity == 'info']
    
    report += f"\n❌ Critical: {len(critical)}\n"
    for issue in critical:
        line_info = f":{issue.line_num}" if issue.line_num > 0 else ""
        report += f"  • {issue.file_path}{line_info} - {issue.message}\n"
        if issue.suggestion:
            report += f"    Fix: {issue.suggestion}\n"
    
    report += f"\n⚠️  Warnings: {len(warnings)}\n"
    for issue in warnings:
        line_info = f":{issue.line_num}" if issue.line_num > 0 else ""
        report += f"  • {issue.file_path}{line_info} - {issue.message}\n"
    
    report += f"\n💡 Info: {len(info)}\n"
    for issue in info:
        report += f"  • {issue.file_path} - {issue.message}\n"
    
    report += "\n" + "="*80 + "\n"
    report += "AI ANALYSIS (CONTEXT & LOGIC)\n"
    report += "="*80 + "\n\n"
    report += ai_output
    
    return report

def print_summary(issues: List[Issue]):
    """Print summary statistics"""
    critical = len([i for i in issues if i.severity == 'critical'])
    warnings = len([i for i in issues if i.severity == 'warning'])
    info = len([i for i in issues if i.severity == 'info'])
    
    print("\n" + "="*80)
    print("📊 SUMMARY")
    print("="*80)
    print(f"❌ Critical: {critical}")
    print(f"⚠️  Warnings: {warnings}")
    print(f"💡 Info: {info}")
    print(f"📝 Total: {len(issues)}")

def main():
    parser = argparse.ArgumentParser(
        description='Yocto Custom Layer Analyzer v2 - Static + AI Review',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ~/workspace/yocto_project meta-aero-bsp
  %(prog)s . meta-aero-bsp meta-aero-distro meta-aero-img
        """
    )
    parser.add_argument('project_path', help='Path to Yocto project root')
    parser.add_argument('layers', nargs='+', help='Custom layer names')
    parser.add_argument('--static-only', action='store_true',
                       help='Run only static analysis (skip AI)')
    
    args = parser.parse_args()
    
    analyze_custom_layers(args.project_path, args.layers)

if __name__ == "__main__":
    main()