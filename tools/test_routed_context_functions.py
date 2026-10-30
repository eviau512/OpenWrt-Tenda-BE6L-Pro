# SPDX-License-Identifier: MIT
"""Extract a fixed C function/struct for CPU compilation, without I/O on import."""
def function(text, marker):
    start = text.index(marker)
    opening = text.index('{', start)
    depth = 0
    for i in range(opening, len(text)):
        depth += (text[i] == '{') - (text[i] == '}')
        if not depth:
            return text[start:i + 1]
    raise AssertionError('Unclosed fixed C declaration: ' + marker)
