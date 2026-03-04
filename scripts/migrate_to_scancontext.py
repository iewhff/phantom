#!/usr/bin/env python3
"""
ScanContext Migration Script

Adds ScanContext integration to scanner modules that don't have it yet.
This script modifies files in-place, adding the necessary import and initialization.

Usage:
    python scripts/migrate_to_scancontext.py scanning/modules/business_logic_scanner.py
    python scripts/migrate_to_scancontext.py --all  # Apply to all missing modules
    python scripts/migrate_to_scancontext.py --check  # Just list modules needing migration

Author: PHANTOM AI
"""

import argparse
import os
import re
import sys
from pathlib import Path


# Pattern to find scan method signature
SCAN_SIGNATURE_PATTERN = re.compile(
    r'(async def scan\s*\(\s*self\s*,\s*'
    r'(?:\w+:\s*str\s*,\s*)?'  # target or host
    r'(?:\w+:\s*dict\[str,\s*Any\]\s*,\s*)?'  # asset_data
    r')'
)

# Pattern to find existing ScanContext import
SCANCONTEXT_IMPORT_PATTERN = re.compile(
    r'from scanning\.scan_context import'
)

# Pattern to find asset_data parameter
ASSET_DATA_PATTERN = re.compile(
    r'async def scan\s*\([^)]*?(\w+):\s*dict\[str,\s*Any\]'
)

# Import line to add
SCANCONTEXT_IMPORT = "from scanning.scan_context import ScanContext"

# Initialization snippet
SCANCONTEXT_INIT = '''
        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers
'''


def needs_migration(filepath: Path) -> bool:
    """Check if a module needs ScanContext migration."""
    content = filepath.read_text()

    # Already has ScanContext
    if SCANCONTEXT_IMPORT_PATTERN.search(content):
        return False

    # Check if it has a scan() method with asset_data
    if not ASSET_DATA_PATTERN.search(content):
        return False

    return True


def migrate_module(filepath: Path, dry_run: bool = False) -> bool:
    """Add ScanContext to a module. Returns True if modified."""
    content = filepath.read_text()

    if not needs_migration(filepath):
        print(f"  SKIP: {filepath.name} (already has ScanContext or no asset_data)")
        return False

    # Find the asset_data parameter name
    match = ASSET_DATA_PATTERN.search(content)
    if not match:
        print(f"  SKIP: {filepath.name} (no asset_data parameter found)")
        return False

    asset_data_name = match.group(1)
    init_code = SCANCONTEXT_INIT.replace("asset_data", asset_data_name)

    # Add import after last import statement
    import_section_end = 0
    for m in re.finditer(r'^(?:from|import)\s+\S+.*$', content, re.MULTILINE):
        import_section_end = max(import_section_end, m.end())

    if import_section_end == 0:
        print(f"  ERROR: {filepath.name} (no imports found)")
        return False

    # Insert import
    new_content = (
        content[:import_section_end] +
        "\n" + SCANCONTEXT_IMPORT +
        content[import_section_end:]
    )

    # Find where to insert initialization (after scan method starts)
    # Look for the docstring end - don't consume trailing indentation
    scan_match = re.search(
        r'async def scan\s*\([^)]*\)[^:]*:\s*'
        r'(?:"""(?:[^"]|"(?!""))*"""\s*\n|\'\'\'(?:[^\']|\'(?!\'\'))*\'\'\'\s*\n)?',
        new_content,
        re.DOTALL
    )

    if scan_match:
        insert_pos = scan_match.end()

        # Check if there's already self._ctx assignment
        if "self._ctx" not in new_content[insert_pos:insert_pos+500]:
            # Preserve existing indentation by adding blank line before init code
            new_content = (
                new_content[:insert_pos] +
                init_code + "\n" +
                new_content[insert_pos:]
            )

    if dry_run:
        print(f"  DRY-RUN: Would modify {filepath.name}")
        return True

    filepath.write_text(new_content)
    print(f"  MIGRATED: {filepath.name}")
    return True


def find_modules_needing_migration(modules_dir: Path) -> list[Path]:
    """Find all modules that need ScanContext migration."""
    results = []
    for f in sorted(modules_dir.glob("*.py")):
        if f.name.startswith("__"):
            continue
        if needs_migration(f):
            results.append(f)
    return results


def main():
    parser = argparse.ArgumentParser(description="Migrate scanner modules to use ScanContext")
    parser.add_argument("files", nargs="*", help="Specific files to migrate")
    parser.add_argument("--all", action="store_true", help="Migrate all modules needing it")
    parser.add_argument("--check", action="store_true", help="Just list modules needing migration")
    parser.add_argument("--dry-run", action="store_true", help="Don't actually modify files")
    parser.add_argument("--priority", action="store_true", help="Only migrate high-priority modules")

    args = parser.parse_args()

    modules_dir = Path("scanning/modules")

    # High-priority modules that benefit most from auth
    priority_modules = {
        "business_logic_scanner.py",
        "creative_exploiter.py",
        "authorization_engine.py",
        "csrf_scanner.py",
        "file_upload_scanner.py",
        "graphql_advanced_scanner.py",
        "race_condition_scanner.py",
        "mass_assignment_scanner.py",
        "rate_limit_scanner.py",
        "oauth_scanner.py",
        "jwt_scanner.py",
        "session_abuse_scanner.py",
        "crlf_scanner.py",
        "open_redirect_scanner.py",
    }

    if args.check:
        print("Modules needing ScanContext migration:")
        for f in find_modules_needing_migration(modules_dir):
            priority = " [PRIORITY]" if f.name in priority_modules else ""
            print(f"  {f.name}{priority}")
        return None

    if args.all:
        files = find_modules_needing_migration(modules_dir)
        if args.priority:
            files = [f for f in files if f.name in priority_modules]
    elif args.files:
        files = [Path(f) for f in args.files]
    else:
        parser.print_help()
        return None

    print(f"Processing {len(files)} modules...")
    migrated = 0
    for f in files:
        if migrate_module(f, args.dry_run):
            migrated += 1

    print(f"\nMigrated: {migrated}/{len(files)} modules")


if __name__ == "__main__":
    main()
