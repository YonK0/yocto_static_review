#!/usr/bin/env python3
"""
Yocto Review - Main Entry Point
Runs static analysis and style checking on Yocto custom layers.
Logs all output to a timestamped file in the log/ directory.
"""

import argparse
import sys
import io
from datetime import datetime
from pathlib import Path

from yocto_static_analysis import YoctoStaticAnalyzer, print_issues, print_summary
from yocto_style_checker import YoctoStyleChecker


class TeeWriter:
    """Write to both console and a string buffer simultaneously."""

    def __init__(self, original_stdout):
        self.original = original_stdout
        self.buffer = io.StringIO()

    def write(self, text):
        self.original.write(text)
        self.buffer.write(text)

    def flush(self):
        self.original.flush()
        self.buffer.flush()

    def getvalue(self):
        return self.buffer.getvalue()


def validate_layers(project_path, layer_names):
    """Verify layers exist and return valid (name, path) pairs."""
    valid = []
    for name in layer_names:
        layer_path = project_path / name
        if layer_path.exists() and layer_path.is_dir():
            valid.append((name, layer_path))
            print(f"  ✅ Found: {name}")
        else:
            print(f"  ❌ Missing: {name}")
    return valid


def run_static_analysis(project_path, layer_paths):
    """Phase 1: Static analysis on all layers."""
    analyzer = YoctoStaticAnalyzer(project_path)
    all_issues = []

    for layer_name, layer_path in layer_paths:
        print(f"\n  🔍 Analyzing {layer_name}...")
        for recipe in layer_path.rglob('*.bb'):
            all_issues.extend(analyzer.analyze_recipe(recipe, layer_name))
        for recipe in layer_path.rglob('*.bbappend'):
            all_issues.extend(analyzer.analyze_recipe(recipe, layer_name))
        all_issues.extend(analyzer.check_layer_structure(layer_path, layer_name))

    all_issues.extend(analyzer.detect_duplicates(layer_paths))

    print_issues(all_issues, "STATIC ANALYSIS")
    print_summary(all_issues)
    return all_issues


def run_style_check(project_path, layer_paths, layer_names):
    """Phase 2: Style guide check on all layers."""
    checker = YoctoStyleChecker(project_path)
    all_issues = []

    for layer_name, layer_path in layer_paths:
        print(f"\n  🔍 Checking {layer_name}...")
        for recipe in layer_path.rglob('*.bb'):
            all_issues.extend(checker.check_recipe(recipe, layer_name))
        for recipe in layer_path.rglob('*.bbappend'):
            all_issues.extend(checker.check_recipe(recipe, layer_name))
        for patch in layer_path.rglob('*.patch'):
            all_issues.extend(checker.check_patch_files(patch, layer_name))
            all_issues.extend(checker.check_cve_patches(patch, layer_name))

    # Print results grouped by rule
    print("\n" + "-" * 80)
    if not all_issues:
        print("  ✅ No style guide violations found!")
        return all_issues

    by_rule = {}
    for issue in all_issues:
        by_rule.setdefault(issue.rule_id, []).append(issue)

    severity_icon = {'error': '❌', 'warning': '⚠️ ', 'info': '💡'}
    for rule_id in sorted(by_rule.keys()):
        issues = by_rule[rule_id]
        print(f"\n  📋 Rule {rule_id}: {issues[0].category.upper()}")
        print("  " + "-" * 78)
        for issue in issues:
            icon = severity_icon[issue.severity]
            line_info = f":{issue.line_num}" if issue.line_num > 0 else ""
            print(f"  {icon} {issue.file_path}{line_info}")
            print(f"     {issue.message}")
            if issue.suggestion:
                print(f"     💡 {issue.suggestion}")

    # Summary
    errors = len([i for i in all_issues if i.severity == 'error'])
    warnings = len([i for i in all_issues if i.severity == 'warning'])
    info = len([i for i in all_issues if i.severity == 'info'])

    print("\n" + "=" * 80)
    print("📊 STYLE CHECK SUMMARY")
    print("=" * 80)
    print(f"  ❌ Errors:   {errors}")
    print(f"  ⚠️  Warnings: {warnings}")
    print(f"  💡 Info:     {info}")
    print(f"  📝 Total:    {len(all_issues)}")

    return all_issues


def main():
    parser = argparse.ArgumentParser(
        description='Yocto Review - Static Analysis & Style Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ~/workspace/yocto_project meta-aero-bsp
  %(prog)s . meta-aero-bsp meta-aero-distro meta-aero-img
        """
    )
    parser.add_argument('project_path', help='Path to Yocto project root')
    parser.add_argument('layers', nargs='+', help='Custom layer names to analyze')
    parser.add_argument('--static-only', action='store_true',
                        help='Run only static analysis (skip style check)')

    args = parser.parse_args()
    project_path = Path(args.project_path).resolve()

    # Setup log directory
    log_dir = Path(__file__).parent / 'log'
    log_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = log_dir / f'yocto_review_{timestamp}.log'

    # Tee stdout so output goes to both console and log buffer
    tee = TeeWriter(sys.stdout)
    sys.stdout = tee

    try:
        print("=" * 80)
        print(f"YOCTO REVIEW - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        print(f"📁 Project: {project_path}")
        print(f"📦 Layers:  {', '.join(args.layers)}")
        print()

        # Validate layers
        print("🔍 Validating layers...")
        layer_paths = validate_layers(project_path, args.layers)
        if not layer_paths:
            print("\n❌ No valid layers found!")
            return

        # Phase 1: Static Analysis
        print("\n" + "=" * 80)
        print("🔍 PHASE 1: STATIC ANALYSIS")
        print("=" * 80)
        run_static_analysis(project_path, layer_paths)

        # Phase 2: Style Check
        if not args.static_only:
            print("\n" + "=" * 80)
            print("🔍 PHASE 2: STYLE GUIDE CHECK")
            print("=" * 80)
            run_style_check(project_path, layer_paths, args.layers)

    finally:
        # Restore stdout and write log
        sys.stdout = tee.original
        log_file.write_text(tee.getvalue(), encoding='utf-8')
        print(f"\n💾 Log saved to: {log_file}")


if __name__ == "__main__":
    main()
