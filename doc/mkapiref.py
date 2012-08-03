#!/usr/bin/env python
# Spdylay - SPDY Library

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
import re, sys, argparse

class FunctionDoc:
    def __init__(self, name, content, domain):
        self.name = name
        self.content = content
        self.domain = domain

    def write(self, out):
        print '''.. {}:: {}'''.format(self.domain, self.name)
        print ''
        for line in self.content:
            print '    {}'.format(line)

class StructDoc:
    def __init__(self, name, content, members, member_domain):
        self.name = name
        self.content = content
        self.members = members
        self.member_domain = member_domain

    def write(self, out):
        if self.name:
            print '''.. type:: {}'''.format(self.name)
            print ''
            for line in self.content:
                print '    {}'.format(line)
            print ''
            for name, content in self.members:
                print '''    .. {}:: {}'''.format(self.member_domain, name)
                print ''
                for line in content:
                    print '''        {}'''.format(line)
            print ''

class MacroDoc:
    def __init__(self, name, content):
        self.name = name
        self.content = content

    def write(self, out):
        print '''.. macro:: {}'''.format(self.name)
        print ''
        for line in self.content:
            print '    {}'.format(line)

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
    alldocs = [('Macros', macros),
               ('Enums', enums),
               ('Types (structs, unions and typedefs)', types),
               ('Functions', functions)]
    for title, docs in alldocs:
        if not docs:
            continue
        print title
        print '-'*len(title)
        for doc in docs:
            doc.write(sys.stdout)
            print ''
        print ''

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
                                          .format(items[2].rstrip(',')))
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
    parser.add_argument('--header', type=argparse.FileType('rb', 0),
                        help='header inserted at the top of the page')
    parser.add_argument('files', nargs='+', type=argparse.FileType('rb', 0),
                        help='source file')
    args = parser.parse_args()
    if args.header:
        print args.header.read()
    for infile in args.files:
        make_api_ref(args.files)
