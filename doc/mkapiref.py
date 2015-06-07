#!/usr/bin/env python
# -*- coding: utf-8 -*-
# nghttp2 - HTTP/2 C Library

# Copyright (c) 2012 Tatsuhiro Tsujikawa

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Generates API reference from C source code.

from __future__ import unicode_literals
from __future__ import print_function # At least python 2.6 is required
import re, sys, argparse, os.path

class FunctionDoc:
    def __init__(self, name, content, domain):
        self.name = name
        self.content = content
        self.domain = domain
        if self.domain == 'function':
            self.funcname = re.search(r'(nghttp2_[^ )]+)\(', self.name).group(1)

    def write(self, out):
        out.write('.. {}:: {}\n'.format(self.domain, self.name))
        out.write('\n')
        for line in self.content:
            out.write('    {}\n'.format(line))

class StructDoc:
    def __init__(self, name, content, members, member_domain):
        self.name = name
        self.content = content
        self.members = members
        self.member_domain = member_domain

    def write(self, out):
        if self.name:
            out.write('.. type:: {}\n'.format(self.name))
            out.write('\n')
            for line in self.content:
                out.write('    {}\n'.format(line))
            out.write('\n')
            for name, content in self.members:
                out.write('    .. {}:: {}\n'.format(self.member_domain, name))
                out.write('\n')
                for line in content:
                    out.write('        {}\n'.format(line))
            out.write('\n')

class MacroDoc:
    def __init__(self, name, content):
        self.name = name
        self.content = content

    def write(self, out):
        out.write('''.. macro:: {}\n'''.format(self.name))
        out.write('\n')
        for line in self.content:
            out.write('    {}\n'.format(line))

def make_api_ref(infiles):
    macros = []
    enums = []
    types = []
    functions = []
    for infile in infiles:
        while True:
            line = infile.readline()
            if not line:
                break
            elif line == '/**\n':
                line = infile.readline()
                doctype = line.split()[1]
                if doctype == '@function':
                    functions.append(process_function('function', infile))
                elif doctype == '@functypedef':
                    types.append(process_function('type', infile))
                elif doctype == '@struct' or doctype == '@union':
                    types.append(process_struct(infile))
                elif doctype == '@enum':
                    enums.append(process_enum(infile))
                elif doctype == '@macro':
                    macros.append(process_macro(infile))
    return macros, enums, types, functions

    alldocs = [('Macros', macros),
               ('Enums', enums),
               ('Types (structs, unions and typedefs)', types),
               ('Functions', functions)]

def output(
        indexfile, macrosfile, enumsfile, typesfile, funcsdir,
        macros, enums, types, functions):
    indexfile.write('''
API Reference
=============

.. toctree::
   :maxdepth: 1

   macros
   enums
   types
''')

    for doc in functions:
        indexfile.write('   {}\n'.format(doc.funcname))

    macrosfile.write('''
Macros
======
''')
    for doc in macros:
        doc.write(macrosfile)

    enumsfile.write('''
Enums
=====
''')
    for doc in enums:
        doc.write(enumsfile)

    typesfile.write('''
Types (structs, unions and typedefs)
====================================
''')
    for doc in types:
        doc.write(typesfile)

    for doc in functions:
        with open(os.path.join(funcsdir, doc.funcname + '.rst'), 'w') as f:
            f.write('''
{funcname}
{secul}

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

'''.format(funcname=doc.funcname, secul='='*len(doc.funcname)))
            doc.write(f)

def process_macro(infile):
    content = read_content(infile)
    line = infile.readline()
    macro_name = line.split()[1]
    return MacroDoc(macro_name, content)

def process_enum(infile):
    members = []
    enum_name = None
    content = read_content(infile)
    while True:
        line = infile.readline()
        if not line:
            break
        elif re.match(r'\s*/\*\*\n', line):
            member_content = read_content(infile)
            line = infile.readline()
            items = line.split()
            member_name = items[0]
            if len(items) >= 3:
                member_content.insert(0, '(``{}``) '\
                                      .format(' '.join(items[2:]).rstrip(',')))
            members.append((member_name, member_content))
        elif line.startswith('}'):
            enum_name = line.rstrip().split()[1]
            enum_name = re.sub(r';$', '', enum_name)
            break
    return StructDoc(enum_name, content, members, 'macro')

def process_struct(infile):
    members = []
    struct_name = None
    content = read_content(infile)
    while True:
        line = infile.readline()
        if not line:
            break
        elif re.match(r'\s*/\*\*\n', line):
            member_content = read_content(infile)
            line = infile.readline()
            member_name = line.rstrip().rstrip(';')
            members.append((member_name, member_content))
        elif line.startswith('}') or\
                (line.startswith('typedef ') and line.endswith(';\n')):
            if line.startswith('}'):
                index = 1
            else:
                index = 3
            struct_name = line.rstrip().split()[index]
            struct_name = re.sub(r';$', '', struct_name)
            break
    return StructDoc(struct_name, content, members, 'member')

def process_function(domain, infile):
    content = read_content(infile)
    func_proto = []
    while True:
        line = infile.readline()
        if not line:
            break
        elif line == '\n':
            break
        else:
            func_proto.append(line)
    func_proto = ''.join(func_proto)
    func_proto = re.sub(r';\n$', '', func_proto)
    func_proto = re.sub(r'\s+', ' ', func_proto)
    func_proto = re.sub(r'NGHTTP2_EXTERN ', '', func_proto)
    return FunctionDoc(func_proto, content, domain)

def read_content(infile):
    content = []
    while True:
        line = infile.readline()
        if not line:
            break
        if re.match(r'\s*\*/\n', line):
            break
        else:
            content.append(transform_content(line.rstrip()))
    return content

def arg_repl(matchobj):
    return '*{}*'.format(matchobj.group(1).replace('*', '\\*'))

def transform_content(content):
    content = re.sub(r'^\s+\* ?', '', content)
    content = re.sub(r'\|([^\s|]+)\|', arg_repl, content)
    content = re.sub(r':enum:', ':macro:', content)
    return content

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate API reference")
    parser.add_argument('index', type=argparse.FileType('w'),
                        help='index output file')
    parser.add_argument('macros', type=argparse.FileType('w'),
                        help='macros section output file.  The filename should be macros.rst')
    parser.add_argument('enums', type=argparse.FileType('w'),
                        help='enums section output file.  The filename should be enums.rst')
    parser.add_argument('types', type=argparse.FileType('w'),
                        help='types section output file.  The filename should be types.rst')
    parser.add_argument('funcsdir',
                        help='functions doc output dir')
    parser.add_argument('files', nargs='+', type=argparse.FileType('r'),
                        help='source file')
    args = parser.parse_args()
    macros = []
    enums = []
    types = []
    funcs = []
    for infile in args.files:
        m, e, t, f = make_api_ref(args.files)
        macros.extend(m)
        enums.extend(e)
        types.extend(t)
        funcs.extend(f)
    funcs.sort(key=lambda x: x.funcname)
    output(
        args.index, args.macros, args.enums, args.types, args.funcsdir,
        macros, enums, types, funcs)
