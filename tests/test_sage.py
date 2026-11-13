"""The Sage scripts: constructs the Sage preparser mishandles, and the output of
model/costs.sage when sage is installed."""
import os
import shutil
import subprocess

from common import FIX, ROOT


def test_sage_preparser_hazards():
    import ast
    import glob
    import io
    import tokenize
    offenders = []
    for path in sorted(glob.glob(os.path.join(ROOT, '*', '*.sage'))):
        name = os.path.basename(path)
        src = open(path, encoding='utf-8').read()
        for lineno, line in enumerate(src.splitlines(), 1):
            if line.endswith('\\'):
                offenders.append(f'{name}:{lineno} backslash continuation')
        try:
            ast.parse(src)
        except SyntaxError as e:
            offenders.append(f'{name}:{e.lineno} {e.msg}')
        try:
            for tok in tokenize.generate_tokens(io.StringIO(src).readline):
                if tok.type == tokenize.NAME and not tok.string.isascii():
                    offenders.append(
                        f'{name}:{tok.start[0]} non-ASCII identifier {tok.string!r}')
        except tokenize.TokenError:
            pass  # unterminated construct — already reported via ast.parse
    assert not offenders, f'sage-file hazards: {offenders}'


def test_sage_costs():
    if not shutil.which('sage'):
        print('  [skip] sage not available')
        return
    args = ['sage', 'model/costs.sage', '--params', 'SPX', '64', '14', '12', '63', '7', '16', '0']
    p = subprocess.run(args, capture_output=True, text=True, cwd=ROOT, timeout=600)
    assert p.returncode == 0, p.stderr[:2000]
    b = FIX['baseline']
    assert f"Size:       {b['size']} bytes" in p.stdout, p.stdout
    assert 'Security:   128.0 bits' in p.stdout, p.stdout
    assert 'C/byte:     0.28  (worst: 0.50)' in p.stdout, p.stdout
