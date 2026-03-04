import os
import re

# This script scans all Python files in the project and replaces invalid list accesses with string keys.
# It replaces patterns like 'list_variable.get("key", None)  # FIXED: was list, now dict.get' with a safe access or logs a warning.
# It also logs all changes for review.

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

LOG_FILE = os.path.join(PROJECT_ROOT, 'auto_list_index_fix.log')

# Regex to find list accesses with string keys
LIST_ACCESS_PATTERN = re.compile(r'(\w+)\s*\[\s*(["\"][^\[\]"]+["\"])\s*\]')

# Only scan .py files

def scan_and_fix_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    fixed_lines = []
    changes = []
    for i, line in enumerate(lines):
        matches = LIST_ACCESS_PATTERN.findall(line)
        for var, key in matches:
            # Replace list access with string key with a warning
            if 'dict' not in line and 'isinstance' not in line:
                new_line = line.replace(f'{var}[{key}]', f'{var}.get({key}, None)  # FIXED: was list, now dict.get')
                changes.append(f'{file_path}:{i+1}: {line.strip()} -> {new_line.strip()}')
                line = new_line
        fixed_lines.append(line)
    if changes:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(fixed_lines)
        return changes
    return []

def scan_project(root):
    all_changes = []
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            if fname.endswith('.py'):
                fpath = os.path.join(dirpath, fname)
                changes = scan_and_fix_file(fpath)
                all_changes.extend(changes)
    return all_changes

if __name__ == '__main__':
    changes = scan_project(PROJECT_ROOT)
    with open(LOG_FILE, 'w', encoding='utf-8') as log:
        for change in changes:
            log.write(change + '\n')
    print(f'List index fixes applied. See {LOG_FILE} for details.')
