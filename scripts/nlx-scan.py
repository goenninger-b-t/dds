#!/usr/bin/env python3
"""nlx-scan — find a non-local exit that CROSSES A LOCK from inside a condition handler.

THE DEFECT (ADR 0098, measured at 16 B/call on SBCL x86_64):

    (or (slot node)
        (dds.pal:with-lock ((lock node))          ; expands to UNWIND-PROTECT
          (or (slot node)
              (handler-case                        ; installs a handler CLOSURE
                  (... (return-from NAME nil) ...) ; <- targets a block OUTSIDE the unwind
                (error () nil)))))

`with-lock` is an UNWIND-PROTECT and HANDLER-CASE installs a handler closure that is normally
stack-allocated. A RETURN-FROM targeting a block OUTSIDE the intervening UNWIND-PROTECT means the exit
must be able to run through the unwind, so the closure loses dynamic extent and is heap-allocated AT
FUNCTION ENTRY -- charged to EVERY call, including every steady-state call that never enters the branch
and never signals.

WHY THIS IS A FORM WALKER AND NOT A GREP: no single construct is the defect. `with-lock` alone,
`handler-case` alone, and `handler-case` containing a `return-from` alone all measure 0.0000 B/call.
Only the NESTING costs. Nesting is exactly what a regex cannot see.

Exit 0 = clean. Exit 1 = violations found (printed as file:line). Exit 2 = usage/parse error.
"""
import sys, os, re

# ---------------------------------------------------------------- reader

class Atom(str):
    """A symbol/number token that remembers where it came from."""
    def __new__(cls, text, line):
        o = super().__new__(cls, text)
        o.line = line
        return o

def parse(src):
    """Parse Lisp source into nested lists of Atom. Tolerant: unknown reader macros become atoms."""
    i, n, line = 0, len(src), 1
    stack, cur = [], []
    while i < n:
        c = src[i]
        if c == '\n':
            line += 1; i += 1; continue
        if c in ' \t\r\f':
            i += 1; continue
        if c == ';':                                    # line comment
            while i < n and src[i] != '\n':
                i += 1
            continue
        if src.startswith('#|', i):                     # block comment (nestable)
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith('#|', i): depth += 1; i += 2
                elif src.startswith('|#', i): depth -= 1; i += 2
                else:
                    if src[i] == '\n': line += 1
                    i += 1
            continue
        if src.startswith('#\\', i):                    # character literal: #\( #\; #\Space
            j = i + 2
            if j < n:
                j += 1
                while j < n and (src[j].isalnum() or src[j] == '-'):
                    j += 1
            cur.append(Atom(src[i:j], line)); i = j; continue
        if c == '"':                                    # string
            j = i + 1
            while j < n:
                if src[j] == '\\': j += 2; continue
                if src[j] == '"': break
                if src[j] == '\n': line += 1
                j += 1
            cur.append(Atom('"..."', line)); i = j + 1; continue
        if c == '|':                                    # |escaped symbol|
            j = src.find('|', i + 1)
            j = n if j < 0 else j + 1
            cur.append(Atom(src[i:j].lower(), line)); i = j; continue
        if c in "'`,":                                  # quote/backquote/unquote: structurally transparent
            i += 1
            if i < n and src[i] == '@': i += 1
            continue
        if c == '(' or src.startswith('#(', i):
            if c == '#': i += 1
            stack.append(cur); cur = []; i += 1; continue
        if c == ')':
            if not stack:                               # stray close paren: ignore, stay tolerant
                i += 1; continue
            done, cur = cur, stack.pop()
            cur.append(done); i += 1; continue
        j = i                                           # ordinary token
        while j < n and src[j] not in ' \t\r\n\f()";':
            j += 1
        if j == i: j = i + 1
        cur.append(Atom(src[i:j].lower(), line)); i = j
    while stack:                                        # unclosed form at EOF: keep what we have
        done, cur = cur, stack.pop()
        cur.append(done)
    return cur

def head(form):
    """The operator symbol of FORM, or None."""
    if isinstance(form, list) and form and isinstance(form[0], Atom):
        return str(form[0])
    return None

def bare(sym):
    """Strip a package qualifier: dds.pal:with-lock -> with-lock."""
    return sym.rsplit(':', 1)[-1] if sym else sym

# ---------------------------------------------------------------- vocabulary

DEFUNS   = {'defun', 'defun*', 'defmethod'}
# Seeded with the EXTERNAL unwinding macros whose expansion is not in src/ and so cannot be learned:
# dds.pal:with-lock expands to bordeaux-threads:with-lock-held, which expands (outside this repo) to
# sb-thread:with-mutex and finally to an UNWIND-PROTECT. Without these seeds the fixpoint below never
# reaches `unwind-protect` and the whole check silently passes everything — which is exactly what the
# gate's own falsification caught.
UNWIND   = {'unwind-protect', 'with-lock-held', 'with-recursive-lock-held', 'with-mutex',
            'with-open-file', 'with-open-stream'}
HANDLER  = {'handler-case', 'handler-bind', 'ignore-errors'}
EXITS    = {'return-from', 'throw', 'go'}

def learn_macros(files):
    """Grow UNWIND/HANDLER with this repo's own macros that expand to those forms.

    Self-maintaining on purpose: a new lock/borrow macro is covered the day it is written, without
    anyone remembering to add it to a list here."""
    unwind, handler = set(UNWIND), set(HANDLER)
    for _ in range(3):                                   # fixpoint: macros built on macros
        grew = False
        for path in files:
            try:
                src = open(path, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            for form in parse(src):
                if head(form) != 'defmacro' or len(form) < 2:
                    continue
                name = bare(str(form[1]))
                flat = _symbols(form)
                if (flat & unwind) and name not in unwind:
                    unwind.add(name); grew = True
                if (flat & handler) and name not in handler:
                    handler.add(name); grew = True
        if not grew:
            break
    return unwind, handler

def _symbols(form, acc=None):
    if acc is None: acc = set()
    if isinstance(form, list):
        for x in form: _symbols(x, acc)
    elif isinstance(form, Atom):
        acc.add(bare(str(form)))
    return acc

# ---------------------------------------------------------------- the rule

def scan_form(form, path, unwind, handler, out):
    """Walk FORM keeping a frame stack, and flag every exit that crosses a lock from inside a handler."""
    def walk(node, stack):
        if not isinstance(node, list) or not node:
            return
        h = bare(head(node)) if head(node) else None

        if h in EXITS and len(node) >= 2 and isinstance(node[1], Atom):
            target = bare(str(node[1]))
            # innermost frame establishing this block
            bi = None
            for k in range(len(stack) - 1, -1, -1):
                if stack[k][0] == 'block' and stack[k][1] == target:
                    bi = k; break
            if bi is not None:
                # between the block and here: an unwind, and inside THAT unwind, a handler
                ui = next((k for k in range(bi + 1, len(stack)) if stack[k][0] == 'unwind'), None)
                if ui is not None and any(stack[k][0] == 'handler' for k in range(ui + 1, len(stack))):
                    out.append((path, node[0].line, target, stack[ui][1], stack[-1][1]))

        frame = None
        if h in DEFUNS and len(node) >= 2 and isinstance(node[1], Atom):
            frame = ('block', bare(str(node[1])))
        elif h == 'block' and len(node) >= 2 and isinstance(node[1], Atom):
            frame = ('block', bare(str(node[1])))
        elif h in unwind:
            frame = ('unwind', h)
        elif h in handler:
            frame = ('handler', h)

        stack2 = stack + [frame] if frame else stack
        for child in node[1:] if frame and frame[0] == 'block' else node:
            walk(child, stack2)

    walk(form, [])

def main(argv):
    files = []
    for root in (argv[1:] or ['src']):
        if os.path.isfile(root):
            files.append(root)
        else:
            for d, _, fs in os.walk(root):
                files.extend(os.path.join(d, f) for f in sorted(fs) if f.endswith('.lisp'))
    files.sort()
    if not files:
        print('nlx-scan: no .lisp files found', file=sys.stderr); return 2

    # Vocabulary is REPO-WIDE, scope is per-invocation: scanning one file must still know that
    # dds.pal:with-lock expands to an UNWIND-PROTECT, or the check silently measures nothing.
    vocab = list(files)
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for d, _, fs in os.walk(os.path.join(here, 'src')):
        vocab.extend(os.path.join(d, f) for f in fs if f.endswith('.lisp'))
    unwind, handler = learn_macros(vocab)
    out = []
    for path in files:
        try:
            src = open(path, encoding='utf-8', errors='replace').read()
        except OSError as e:
            print(f'nlx-scan: {path}: {e}', file=sys.stderr); return 2
        for form in parse(src):
            scan_form(form, path, unwind, handler, out)

    if out:
        print(f'nlx-scan: {len(out)} non-local exit(s) crossing a lock from inside a handler:')
        for path, line, target, uw, hd in out:
            print(f'  {path}:{line}: exit to block {target} crosses {uw} from inside {hd}')
        return 1
    print(f'nlx-scan: clean — {len(files)} file(s), '
          f'{len(unwind)} unwind form(s), {len(handler)} handler form(s) known')
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
