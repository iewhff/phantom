import os
import re
import shutil

# Variáveis e padrões que você pode ajustar
DICT_VARS = ["data", "asset_data", "resp_data"]
PATTERNS = [
    r"{var}\[[\"\']",  # data.get("key", None)  # FIXED: was list, now dict.get
    r"{var}\.get\(",      # data.get(
]

BACKUP_SUFFIX = ".bak_typecheck"


def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        inserted = False
        for var in DICT_VARS:
            for pat in PATTERNS:
                regex = re.compile(pat.format(var=var))
                if regex.search(line):
                    indent = len(line) - len(line.lstrip())
                    check = ' ' * indent + f'if isinstance({var}, dict):\n'
                    # Evita duplicar checagens
                    if i == 0 or f'isinstance({var}, dict)' not in lines[i-1]:
                        new_lines.append(check)
                        new_lines.append(' ' * (indent + 4) + line.lstrip())
                        inserted = True
                        break
            if inserted:
                break
        if not inserted:
            new_lines.append(line)
        i += 1

    # Backup antes de sobrescrever
    shutil.copy(filepath, filepath + BACKUP_SUFFIX)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)


def walk_and_process(root):
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if filename.endswith('.py'):
                process_file(os.path.join(dirpath, filename))

if __name__ == '__main__':
    walk_and_process('scanning')
    print('Type checks inseridos automaticamente. Backups criados com sufixo', BACKUP_SUFFIX)
