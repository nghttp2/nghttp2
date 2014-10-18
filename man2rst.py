#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import sys
import re

def man2rst(f):
    expect_arg = False
    in_arg = False

    for line in f:
        line = line.rstrip()

        if re.match(r'\.\\"', line):
            # comment
            continue

        if re.match(r'\.TH ', line):
            # title
            title = line.split()[1].lower()
            sys.stdout.write('.. program:: {}\n\n'.format(title))
            title += '(1)'
            sys.stdout.write('{}\n'.format(title))
            sys.stdout.write('=' * len(title))
            sys.stdout.write('\n')
            continue

        if re.match(r'\.SH ', line):
            # section
            expect_arg = False
            in_arg = False
            section = line.split(' ', 1)[1].strip('"')
            sys.stdout.write('\n{}\n'.format(section))
            sys.stdout.write('-' * len(section))
            sys.stdout.write('\n')
            continue

        if re.match(r'\.br', line):
            sys.stdout.write('\n')
            continue

        if re.match(r'\.B ', line):
            prog = line.split(' ', 1)[1]
            sys.stdout.write('**{}** '.format(prog))
            continue

        if re.match(r'\.SS ', line):
            # subsection
            expect_arg = False
            in_arg = False
            subsection = line.split(' ', 1)[1].strip('"').rstrip(':')
            sys.stdout.write('\n{}\n'.format(subsection))
            sys.stdout.write('^' * len(subsection))
            sys.stdout.write('\n')
            continue

        if re.match(r'\.(T|H|I)P', line):
            expect_arg = True
            in_arg = False
            sys.stdout.write('\n')
            continue

        if expect_arg and line.startswith('<'):
            expect_arg = False
            in_arg = True
            positional_arg = line.lstrip('<').rstrip('>')
            sys.stdout.write('.. option:: {}\n\n'.format(positional_arg))
            continue

        if expect_arg and line.startswith('('):
            expect_arg = False
            in_arg = True
            sys.stdout.write('.. describe:: {}\n\n'.format(line))
            continue

        if expect_arg:
            expect_arg = False

            m = re.match(r'(\\fB.*?\\fR(?:, \\fB.*?\\fR)?[\S]*)(.*)', line)
            if not m:
                sys.stdout.write('{}\n'.format(process_text(line)))
                continue

            in_arg = True
            optional_arg = process_arg(m.group(1))
            text = m.group(2).strip()
            sys.stdout.write('.. option:: {}\n\n'.format(optional_arg))
            sys.stdout.write('    {}\n'.format(process_text(text)))
            continue

        if in_arg:
            sys.stdout.write('    {}\n'.format(process_text(line)))
            continue

        sys.stdout.write('{}\n'.format(process_text(line)))

def process_arg(text):
    text = re.sub(r'\\fB(.*?)\\fR', '\\1', text)
    text = re.sub(r'\\-', '-', text)

    return text

def process_text(text):
    text = re.sub(r'\\fI\\,(.*?)\\/\\f(?:R|P)', '\\1', text)
    text = re.sub(r'\\fB\\(-[^1].*?)\\fR(\s|[,.]|\Z)', ':option:`\\1`\\2', text)
    text = re.sub(r'\\fB(.*?)\\fR', '\\1', text)
    text = re.sub(r'\\-', '-', text)
    text = re.sub(r'\*', '\\*', text)
    text = re.sub(r'\\&', '', text)

    return text

if __name__ == '__main__':
    man2rst(sys.stdin)
