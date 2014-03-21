#!/usr/bin/env python3
#
# Speedsnake (http://code.google.com/p/speedsnake/)
# Copyright (c) 2013-2014 Matt Craighead
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
# associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute,
# sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
# NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
# OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# This is a quick and dirty AArch64 assembler written entirely in Python.

import argparse
import re
import struct

# magic bytes that we mostly don't care about
elf_header = bytes.fromhex('7f454c46020101000000000000000000')
elf_header += struct.pack('<HHIQQQIHHHHHH', 1, 0xB7, 1, 0, 0, 0, 0, 0x40, 0, 0, 0x40, 7, 4)
section_headers = bytes(0x40) # strange all-zero section header
section_headers += struct.pack('<IIQQQQIIQQ', 0x1B, 1, 6, 0, 0, 0, 0, 0, 1, 0)
section_headers += struct.pack('<IIQQQQIIQQ', 0x21, 1, 3, 0, 0, 0, 0, 0, 1, 0)
section_headers += struct.pack('<IIQQQQIIQQ', 0x27, 8, 3, 0, 0, 0, 0, 0, 1, 0)
section_headers += struct.pack('<IIQQQQIIQQ', 0x11, 3, 0, 0, 0, 0, 0, 0, 1, 0)
section_headers += struct.pack('<IIQQQQIIQQ', 0x01, 2, 0, 0, 0, 0, 6, 0, 8, 0x18)
section_headers += struct.pack('<IIQQQQIIQQ', 0x09, 3, 0, 0, 0, 0, 0, 0, 1, 0)

def pad_to_8b(x):
    if len(x) & 7:
        return x + bytes(8 - (len(x) & 7))
    else:
        return x

def make_elf(filename, labels, code):
    # Build section names (hardcoded for our purposes, since we only really care about "code")
    section_names = b'\0.symtab\0.strtab\0.shstrtab\0.text\0.data\0.bss\0'

    # Build string table (just a list of null-terminated strings for the filename and all the function names)
    string_table = b'\0'
    symbol_string_table_offsets = {}
    for (i, function) in enumerate(labels):
        symbol_string_table_offsets[function[0]] = len(string_table)
        string_table += function[0].encode() + b'\0'
        if i == 0:
            symbol_string_table_offsets['$x'] = len(string_table)
            string_table += b'$x\0'

    # Build symbol table (string-table-pointer -> code-offset), putting local symbols first
    symbol_table  = struct.pack('<IHHQQ', 0, 0, 0, 0, 0)
    symbol_table += struct.pack('<IHHQQ', 0, 3, 1, 0, 0)
    symbol_table += struct.pack('<IHHQQ', 0, 3, 2, 0, 0)
    symbol_table += struct.pack('<IHHQQ', 0, 3, 3, 0, 0)
    for (i, function) in enumerate(labels):
        symbol_table += struct.pack('<IHHQQ', symbol_string_table_offsets[function[0]], 0, 1, function[1], 0)
        if i == 0:
            symbol_table += struct.pack('<IHHQQ', symbol_string_table_offsets['$x'], 0, 1, 0, 0)

    # Construct the full ELF file
    elf_file = bytearray(elf_header)
    elf_file += code
    elf_file += section_names
    elf_file = pad_to_8b(elf_file)
    elf_file[0x28:0x30] = struct.pack('<Q', len(elf_file))
    section_headers_local = bytearray(section_headers)
    section_headers_local[0x58:0x68] = struct.pack('<QQ', 0x40, len(code))
    section_headers_local[0x98:0xA8] = struct.pack('<QQ', 0x40 + len(code), 0)
    section_headers_local[0xD8:0xE8] = struct.pack('<QQ', 0x40 + len(code), 0)
    section_headers_local[0x118:0x128] = struct.pack('<QQ', 0x40 + len(code), len(section_names))
    section_headers_local[0x158:0x168] = struct.pack('<QQ', len(elf_file) + len(section_headers_local), len(symbol_table))
    section_headers_local[0x16C:0x170] = struct.pack('<I', 5 + len(labels))
    section_headers_local[0x198:0x1A8] = struct.pack('<QQ', len(elf_file) + len(section_headers_local) + len(symbol_table), len(string_table))
    elf_file += section_headers_local
    elf_file += symbol_table
    elf_file += string_table
    return elf_file

tokens = [
    ('ID', r'[A-Za-z_][A-Za-z0-9_]*'),
    ('NUMBER', r'#0(x[A-Fa-f0-9_]+)?|#[1-9][0-9]*'),
    ('SYMBOL', r'[\*+\-,\[\]]'),
    ('SKIP', r'[ \t]'),
]
r = re.compile('|'.join('(?P<%s>%s)' % pair for pair in tokens)).match

w_regs = {'w%d' % i: i for i in range(31)}
x_regs = {'x%d' % i: i for i in range(31)}

# XXX crc32*, smulh, umulh
logic_ops = {
    'and': (0, 0), 'bic': (0, 1),
    'orr': (1, 0), 'orn': (1, 1),
    'eor': (2, 0), 'eon': (2, 1),
    'ands': (3, 0), 'bics': (3, 1),
}
dp_1_src = {'rbit': 0, 'rev16': 1, 'rev32': 2, 'rev': 3, 'clz': 4, 'cls': 5}
dp_2_src = {'udiv': 2, 'sdiv': 3, 'lslv': 8, 'lsrv': 9, 'asrv': 10, 'rorv': 11}
dp_3_src = {
    'madd': (0, 0),
    'msub': (0, 1),
    'smaddl': (1, 0),
    'smsubl': (1, 1),
    'umaddl': (5, 0),
    'umsubl': (5, 1),
}
hint_aliases = {'nop': 0, 'yield': 1, 'wfe': 2, 'wfi': 3, 'sev': 4, 'sevl': 5}
shift_mod_types = {'lsl': 0, 'lsr': 1, 'asr': 2}

sys_regs = {
    'scr_el3':    (3,  1, 6, 1, 0),
    'cptr_el3':   (3,  1, 6, 1, 2),
    'spsr_el3':   (3,  4, 6, 0, 0),
    'elr_el3':    (3,  4, 6, 0, 1),
    'cntfrq_el0': (3, 14, 3, 0, 0),
}

class ShiftModifier:
    def __init__(self, shift, imm):
        self.shift = shift_mod_types[shift]
        self.imm = imm

class Parser:
    def __init__(self):
        self.labels = []
        self.code = b''
        self.cur_macro_args = None

    def find_label_offset(self, label):
        for (name, offset) in self.labels:
            if name == label:
                return offset
        raise RuntimeError("could not find label '%s'" % label)

    def line_to_code(self, line):
        if line.endswith(':'):
            self.labels.append((line[:-1], len(self.code)))
            return # XXX skip

        tokens = []
        pos = line_start = 0
        mo = r(line)
        while mo is not None:
            typ = mo.lastgroup
            if typ != 'SKIP':
                val = mo.group(typ)
                if typ == 'NUMBER':
                    val = int(val[1:], 0)
                tokens.append(val)
            pos = mo.end()
            mo = r(line, pos)
        if pos != len(line):
            raise RuntimeError('Unexpected character %r' % line[pos])

        if isinstance(tokens[-1], int) and tokens[-2] in shift_mod_types and tokens[-3] == ',':
            tokens[-2:] = [ShiftModifier(tokens[-2], tokens[-1])]

        # name and comma-separated args
        name = tokens[0]
        if len(tokens) == 1:
            args = []
        else:
            assert not len(tokens) & 1
            for i in range(2, len(tokens), 2):
                assert tokens[i] == ','
            args = tokens[1::2]

        if name == 'ret':
            if not args:
                args = ['x30']
            assert len(args) == 1, args
            reg = x_regs[args[0]]
            inst = 0xD65F0000 | (reg << 5)
        elif name == 'hint':
            assert len(args) == 1, args
            assert isinstance(args[0], int)
            assert 0 <= args[0] <= 127
            inst = 0xD503201F | (args[0] << 5)
        elif name in hint_aliases:
            inst = 0xD503201F | (hint_aliases[name] << 5)
        elif name in {'add', 'adds', 'sub', 'subs'}:
            assert 3 <= len(args) <= 4, args
            sf = args[0] in x_regs
            op = name in {'sub', 'subs'}
            s = name in {'adds', 'subs'}
            r_dst = x_regs[args[0]] if sf else w_regs[args[0]]
            r_src0 = x_regs[args[1]] if sf else w_regs[args[1]]
            if isinstance(args[2], int):
                imm = args[2]
                shift = 0
                if imm >= 0x1000 and not (imm & 0xFFF):
                    imm >>= 12
                    shift = 1
                assert 0 <= imm <= 0xFFF
                inst = 0x11000000 | (sf << 31) | (op << 30) | (s << 29) | (shift << 22) | (imm << 10) | (r_src0 << 5) | r_dst
            else:
                shift = 0
                imm = 0
                if len(args) == 4:
                    assert isinstance(args[3], ShiftModifier), args[3]
                    shift = args[3].shift
                    imm = args[3].imm
                r_src1 = x_regs[args[2]] if sf else w_regs[args[2]]
                inst = 0x0B000000 | (sf << 31) | (op << 30) | (s << 29) | (shift << 22) | (r_src1 << 16) | (imm << 10) | (r_src0 << 5) | r_dst
        elif name in {'adc', 'adcs', 'sbc', 'sbcs'}:
            assert len(args) == 3, args
            sf = args[0] in x_regs
            op = name in {'sbc', 'sbcs'}
            s = name in {'adcs', 'sbcs'}
            r_dst = x_regs[args[0]] if sf else w_regs[args[0]]
            r_src0 = x_regs[args[1]] if sf else w_regs[args[1]]
            r_src1 = x_regs[args[2]] if sf else w_regs[args[2]]
            inst = 0x1A000000 | (sf << 31) | (op << 30) | (s << 29) | (r_src1 << 16) | (r_src0 << 5) | r_dst
        elif name in logic_ops:
            assert 3 <= len(args) <= 4, args
            if isinstance(args[2], int):
                assert len(args) == 3, args
                sf = args[0] in x_regs
                assert sf # XXX
                r_dst = x_regs[args[0]] if sf else w_regs[args[0]]
                r_src0 = x_regs[args[1]] if sf else w_regs[args[1]]
                imm = args[2]
                (opc, n) = logic_ops[name]
                if n:
                    imm ^= 0xFFFFFFFFFFFFFFFF
                if imm == 0x400:
                    (n, immr, imms) = (1, 54, 0) # 1 ROR 54
                elif imm == 0xFFFFFFFFFFFFFBFF:
                    (n, immr, imms) = (1, 53, 62) # (63 1 bits) ROR 53
                else:
                    assert False, imm
                inst = 0x12000000 | (sf << 31) | (opc << 29) | (n << 22) | (immr << 16) | (imms << 10) | (r_src0 << 5) | r_dst
            else:
                shift = 0
                imm = 0
                if len(args) == 4:
                    shift = args[3].shift
                    imm = args[3].imm
                sf = args[0] in x_regs
                (opc, n) = logic_ops[name]
                r_dst = x_regs[args[0]] if sf else w_regs[args[0]]
                r_src0 = x_regs[args[1]] if sf else w_regs[args[1]]
                r_src1 = x_regs[args[2]] if sf else w_regs[args[2]]
                inst = 0x0A000000 | (sf << 31) | (opc << 29) | (shift << 22) | (n << 21) | (r_src1 << 16) | (imm << 10) | (r_src0 << 5) | r_dst
        elif name in dp_1_src:
            assert len(args) == 2, args
            sf = args[0] in x_regs
            if not sf:
                assert name != 'rev32'
                if name == 'rev':
                    name = 'rev32'
            opcode = dp_1_src[name]
            r_dst = x_regs[args[0]] if sf else w_regs[args[0]]
            r_src = x_regs[args[1]] if sf else w_regs[args[1]]
            inst = 0x5AC00000 | (sf << 31) | (opcode << 10) | (r_src << 5) | r_dst
        elif name in dp_2_src:
            assert len(args) == 3, args
            sf = args[0] in x_regs
            opcode = dp_2_src[name]
            r_dst = x_regs[args[0]] if sf else w_regs[args[0]]
            r_src0 = x_regs[args[1]] if sf else w_regs[args[1]]
            r_src1 = x_regs[args[2]] if sf else w_regs[args[2]]
            inst = 0x1AC00000 | (sf << 31) | (opcode << 10) | (r_src1 << 16) | (r_src0 << 5) | r_dst
        elif name in dp_3_src:
            assert len(args) == 4, args
            sf = args[0] in x_regs
            (o31, o0) = dp_3_src[name]
            if name in {'smaddl', 'smsubl', 'umaddl', 'umsubl'}:
                assert sf
                r_dst = x_regs[args[0]]
                r_src0 = w_regs[args[1]]
                r_src1 = w_regs[args[2]]
                r_src2 = x_regs[args[3]]
            else:
                r_dst = x_regs[args[0]] if sf else w_regs[args[0]]
                r_src0 = x_regs[args[1]] if sf else w_regs[args[1]]
                r_src1 = x_regs[args[2]] if sf else w_regs[args[2]]
                r_src2 = x_regs[args[3]] if sf else w_regs[args[3]]
            inst = 0x1B000000 | (sf << 31) | (o31 << 21) | (o0 << 15) | (r_src1 << 16) | (r_src2 << 10) | (r_src0 << 5) | r_dst
        elif name == 'mov':
            assert len(args) == 2, args
            sf = args[0] in x_regs
            assert isinstance(args[1], int), args[1]
            r_dst = x_regs[args[0]] if sf else w_regs[args[0]]
            imm = args[1]
            shift = 0
            while imm >= 0x10000 and not (imm & 0xFFFF):
                imm >>= 16
                shift += 1
            inst = 0x52800000 | (sf << 31) | (shift << 21) | (imm << 5) | r_dst
        elif name == 'movk':
            assert len(args) == 3, args
            sf = args[0] in x_regs
            assert isinstance(args[1], int), args[1]
            assert isinstance(args[2], ShiftModifier), args[2]
            assert args[2].shift == 0 # must be LSL
            assert args[2].imm == 16
            r_dst = x_regs[args[0]] if sf else w_regs[args[0]]
            imm = args[1]
            shift = 1
            inst = 0x72800000 | (sf << 31) | (shift << 21) | (imm << 5) | r_dst
        elif name == 'msr':
            assert len(args) == 2, args
            r_src = x_regs[args[1]]
            (o0, crn, op1, crm, op2) = sys_regs[args[0]]
            inst = 0xD5100000 | (o0 << 19) | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5) | r_src
        elif name == 'mrs':
            assert len(args) == 2, args
            r_dst = x_regs[args[0]]
            (o0, crn, op1, crm, op2) = sys_regs[args[1]]
            inst = 0xD5300000 | (o0 << 19) | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5) | r_dst
        elif name == 'eret':
            assert not args, args
            inst = 0xD69F03E0
        else:
            raise RuntimeError("don't know how to parse line %s" % tokens)
        self.code += struct.pack('<I', inst)

def asm(filename, bin):
    parser = Parser()
    with open(filename) as f:
        for line in f:
            if '//' in line:
                line = line[:line.index('//')] # remove comments
            line = line.strip()
            if not line:
                continue # skip blank lines

            parser.line_to_code(line)

    if bin:
        return parser.code
    else:
        return make_elf(filename, parser.labels, parser.code)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin', action='store_true')
    parser.add_argument('input_filename')
    parser.add_argument('output_filename')
    args = parser.parse_args()

    out = asm(args.input_filename, args.bin)
    with open(args.output_filename, 'wb') as f:
        f.write(out)

if __name__ == '__main__':
    main()
