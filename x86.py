#!/usr/bin/env python3
#
# Speedsnake (http://code.google.com/p/speedsnake/)
# Copyright (c) 2013 Matt Craighead
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

# This is a quick and dirty x86-64 assembler written entirely in Python.  It is not a full
# implementation of x86 -- it has a number of significant limitations and missing instructions.
# We intend to fix most of those limitations, with the exception of x87 and MMX, which we do not
# expect to ever support.  Also, at present, there are no plans to support 16-bit or 32-bit mode.

import argparse
import re
import struct

# magic bytes that we mostly don't care about
elf_header = bytes.fromhex('7f454c46020101000000000000000000')
elf_header += struct.pack('<HHIQQQIHHHHHH', 1, 62, 1, 0, 0, 0x40, 0, 0x40, 0, 0, 0x40, 5, 2)
elf_header += bytes(0x40) # strange all-zero section header
elf_header += struct.pack('<IIQQQQIIQQ', 0x01, 1, 2, 0, 0, 0, 0, 0, 1, 0) # code
elf_header += struct.pack('<IIQQQQIIQQ', 0x06, 3, 0, 0, 0, 0, 0, 0, 1, 0) # .shstrtab
elf_header += struct.pack('<IIQQQQIIQQ', 0x10, 2, 0, 0, 0, 0, 4, 0, 4, 0x18) # .symtab
elf_header += struct.pack('<IIQQQQIIQQ', 0x18, 3, 0, 0, 0, 0, 0, 0, 1, 0) # .strtab

def pad_to_16b(x):
    if len(x) & 15:
        return x + bytes(16 - (len(x) & 15))
    else:
        return x

def make_elf(filename, labels, globals, code):
    # Build section names (hardcoded for our purposes, since we only really care about "code")
    section_names = b'\0code\0.shstrtab\0.symtab\0.strtab\0'
    assert not len(section_names) & 15 # conveniently doesn't need 16B padding

    # Build string table (just a list of null-terminated strings for the filename and all the function names)
    string_table = b'\0' + filename.encode() + b'\0'
    symbol_string_table_offsets = {}
    for function in labels:
        symbol_string_table_offsets[function[0]] = len(string_table)
        string_table += function[0].encode() + b'\0'

    # Build symbol table (string-table-pointer -> code-offset), putting local symbols first
    symbol_table  = struct.pack('<IHHQQ', 0, 0, 0, 0, 0)
    symbol_table += struct.pack('<IHHQQ', 1, 4, 0xFFF1, 0, 0)
    symbol_table += struct.pack('<IHHQQ', 0, 3, 1, 0, 0)
    for function in labels:
        if function[0] not in globals:
            symbol_table += struct.pack('<IHHQQ', symbol_string_table_offsets[function[0]], 0, 1, function[1], 0)
    for function in labels:
        if function[0] in globals:
            symbol_table += struct.pack('<IHHQQ', symbol_string_table_offsets[function[0]], 0x10, 1, function[1], 0)

    # Construct the full ELF file
    elf_file = bytearray(elf_header)
    for (i, section) in enumerate([code, section_names, symbol_table, string_table]):
        header_offset = 0x98 + 0x40*i
        elf_file[header_offset:header_offset+16] = struct.pack('<QQ', len(elf_file), len(section))
        elf_file += pad_to_16b(section)
    elf_file[0x12C:0x130] = struct.pack('<I', 3 + len(labels) - len(globals)) # "one greater than the symbol table index of the last local symbol"
    return elf_file

def make_obj(filename, labels, globals, code):
    obj_file = struct.pack('<IIIIIIIIIIIIIII',
        0x18664, 0, 0x3C + len(code), 5 + len(labels), 0, 0x65646F63, 0, 0, 0, len(code), 0x3C, 0x3C + len(code), 0, 0, 0x60500020)
    obj_file += code
    obj_file += bytes.fromhex('2E 66 69 6C 65 00 00 00 00 00 00 00 FE FF 00 00 67 01')
    filename = filename.encode()[:18] # just gets truncated after 18 bytes
    obj_file += filename + bytes(18-len(filename))
    obj_file += bytes.fromhex('63 6F 64 65 00 00 00 00 00 00 00 00 01 00 00 00 03 01')
    obj_file += struct.pack('<I', len(code))
    obj_file += bytes.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00')
    obj_file += bytes.fromhex('2E 61 62 73 6F 6C 75 74 00 00 00 00 FF FF 00 00 03 00')
    string_table_size = 4
    string_table = []
    for function in labels:
        name = function[0].encode()
        if len(name) > 8:
            obj_file += struct.pack('<II', 0, string_table_size)
            string_table.append(name)
            string_table_size += len(name) + 1
        else:
            obj_file += name + bytes(8 - len(name))
        obj_file += struct.pack('<IHHBB', function[1], 1, 0, 2 if function[0] in globals else 3, 0)
    obj_file += struct.pack('<I', string_table_size)
    for name in string_table:
        obj_file += name + b'\0'
    return obj_file

reg8_hi_nums = {'ah':  4, 'ch':  5, 'dh':  6, 'bh':  7}
reg8_nums    = {'al':  0, 'cl':  1, 'dl':  2, 'bl':  3, 'spl': 4, 'bpl': 5, 'sil': 6, 'dil': 7}
reg16_nums   = {'ax':  0, 'cx':  1, 'dx':  2, 'bx':  3, 'sp':  4, 'bp':  5, 'si':  6, 'di':  7}
reg32_nums   = {'eax': 0, 'ecx': 1, 'edx': 2, 'ebx': 3, 'esp': 4, 'ebp': 5, 'esi': 6, 'edi': 7}
reg64_nums   = {'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3, 'rsp': 4, 'rbp': 5, 'rsi': 6, 'rdi': 7}
for i in range(8, 16):
    reg8_nums['r%db' % i] = i
    reg16_nums['r%dw' % i] = i
    reg32_nums['r%dd' % i] = i
    reg64_nums['r%d' % i] = i

xmm_reg_nums = {'xmm%d' % i: i for i in range(16)}
ymm_reg_nums = {'ymm%d' % i: i for i in range(16)}

conditions = {
    'a':  0x7,
    'ae': 0x3,
    'b':  0x2,
    'be': 0x6,
    'c':  0x2,
    'e':  0x4,
    'g':  0xF,
    'ge': 0xD,
    'l':  0xC,
    'le': 0xE,
    'nc': 0x3,
    'ne': 0x5,
    'no': 0x1,
    'np': 0xB,
    'ns': 0x9,
    'nz': 0x5,
    'o':  0x0,
    'p':  0xA,
    's':  0x8,
    'z':  0x4,
}

trivial_opcodes = {
    'insb':       b'\x6C',
    'insw':       b'\x66\x6D',
    'insd':       b'\x6D',
    'outsb':      b'\x6E',
    'outsw':      b'\x66\x6F',
    'outsd':      b'\x6F',
    'pause':      b'\xF3\x90',
    'nop':        b'\x90',
    'pushf':      b'\x9C',
    'pushfq':     b'\x9C',
    'popf':       b'\x9D',
    'popfq':      b'\x9D',
    'cwde':       b'\x98',
    'cwd':        b'\x66\x99',
    'cdq':        b'\x99',
    'cqo':        b'\x48\x99',
    'wait':       b'\x9B',
    'fwait':      b'\x9B',
    'sahf':       b'\x9E',
    'lahf':       b'\x9F',
    'movsb':      b'\xA4',
    'movsw':      b'\x66\xA5',
    'movsd':      b'\xA5',
    'movsq':      b'\x48\xA5',
    'cmpsb':      b'\xA6',
    'cmpsw':      b'\x66\xA7',
    'cmpsd':      b'\xA7',
    'cmpsq':      b'\x48\xA7',
    'stosb':      b'\xAA',
    'stosw':      b'\x66\xAB',
    'stosd':      b'\xAB',
    'stosq':      b'\x48\xAB',
    'lodsb':      b'\xAC',
    'lodsw':      b'\x66\xAD',
    'lodsd':      b'\xAD',
    'lodsq':      b'\x48\xAD',
    'scasb':      b'\xAE',
    'scasw':      b'\x66\xAF',
    'scasd':      b'\xAF',
    'scasq':      b'\x48\xAF',
    'ret':        b'\xC3',
    'retn':       b'\xC3',
    'leave':      b'\xC9',
    'retf':       b'\xCB',
    'iret':       b'\xCF',
    'iretd':      b'\xCF',
    'iretq':      b'\x48\xCF',
    'xlat':       b'\xD7',
    'xlatb':      b'\xD7',
    'hlt':        b'\xF4',
    'cmc':        b'\xF5',
    'clc':        b'\xF8',
    'stc':        b'\xF9',
    'cli':        b'\xFA',
    'sti':        b'\xFB',
    'cld':        b'\xFC',
    'std':        b'\xFD',
    'vmcall':     b'\x0F\x01\xC1',
    'vmlaunch':   b'\x0F\x01\xC2',
    'vmresume':   b'\x0F\x01\xC3',
    'vmxoff':     b'\x0F\x01\xC4',
    'vmfunc':     b'\x0F\x01\xD4',
    'monitor':    b'\x0F\x01\xC8',
    'mwait':      b'\x0F\x01\xC9',
    'xgetbv':     b'\x0F\x01\xD0',
    'xsetbv':     b'\x0F\x01\xD1',
    'swapgs':     b'\x0F\x01\xF8',
    'rdtscp':     b'\x0F\x01\xF9',
    'syscall':    b'\x0F\x05',
    'clts':       b'\x0F\x06',
    'sysret':     b'\x0F\x07',
    'invd':       b'\x0F\x08',
    'wbinvd':     b'\x0F\x09',
    'ud2':        b'\x0F\x0B',
    'wrmsr':      b'\x0F\x30',
    'rdtsc':      b'\x0F\x31',
    'rdmsr':      b'\x0F\x32',
    'rdpmc':      b'\x0F\x33',
    'sysenter':   b'\x0F\x34',
    'sysexit':    b'\x0F\x35',
    'getsec':     b'\x0F\x37',
    'emms':       b'\x0F\x77',
    'cpuid':      b'\x0F\xA2',
    'rsm':        b'\x0F\xAA',
    'lfence':     b'\x0F\xAE\xE8',
    'mfence':     b'\x0F\xAE\xF0',
    'sfence':     b'\x0F\xAE\xF8',
    'vzeroupper': b'\xC5\xF8\x77',
    'vzeroall':   b'\xC5\xFC\x77',
}

reg_only_opcodes = {
    # These are not actually reg-only, but supporting them on memory would require parsing "dword ptr", etc.
    'not':      (b'',     b'\xF7', 2),
    'neg':      (b'',     b'\xF7', 3),
    'mul':      (b'',     b'\xF7', 4),
    'imul':     (b'',     b'\xF7', 5),
    'div':      (b'',     b'\xF7', 6),
    'idiv':     (b'',     b'\xF7', 7),
    'inc':      (b'',     b'\xFF', 0),
    'dec':      (b'',     b'\xFF', 1),

    # These are actually reg-only.
    'rdfsbase': (b'\xF3', b'\x0F\xAE', 0),
    'rdgsbase': (b'\xF3', b'\x0F\xAE', 1),
    'rdrand':   (b'',     b'\x0F\xC7', 6),
    'wrfsbase': (b'\xF3', b'\x0F\xAE', 2),
    'wrgsbase': (b'\xF3', b'\x0F\xAE', 3),
}

mem_only_opcodes = {
    'clflush':     (0, b'\x0F\xAE', 7),
    'invlpg':      (0, b'\x0F\x01', 7),
    'ldmxcsr':     (0, b'\x0F\xAE', 2),
    'lgdt':        (0, b'\x0F\x01', 2),
    'lidt':        (0, b'\x0F\x01', 3),
    'lldt':        (0, b'\x0F\x00', 2),
    'lmsw':        (0, b'\x0F\x01', 6),
    'ltr':         (0, b'\x0F\x00', 3),
    'prefetcht0':  (0, b'\x0F\x18', 1),
    'prefetcht1':  (0, b'\x0F\x18', 2),
    'prefetcht2':  (0, b'\x0F\x18', 3),
    'prefetchnta': (0, b'\x0F\x18', 0),
    'sgdt':        (0, b'\x0F\x01', 0),
    'sidt':        (0, b'\x0F\x01', 1),
    'sldt':        (0, b'\x0F\x00', 0),
    'smsw':        (0, b'\x0F\x01', 4),
    'stmxcsr':     (0, b'\x0F\xAE', 3),
    'str':         (0, b'\x0F\x00', 1),
    'verr':        (0, b'\x0F\x00', 4),
    'verw':        (0, b'\x0F\x00', 5),
    'xrstor':      (0, b'\x0F\xAE', 5),
    'xrstor64':    (1, b'\x0F\xAE', 5),
    'xsave':       (0, b'\x0F\xAE', 4),
    'xsave64':     (1, b'\x0F\xAE', 4),
    'xsaveopt':    (0, b'\x0F\xAE', 6),
    'xsaveopt64':  (1, b'\x0F\xAE', 6),
}

basic_opcodes = {'add': 0, 'or': 1, 'adc': 2, 'sbb': 3, 'and': 4, 'sub': 5, 'xor': 6, 'cmp': 7}
shift_opcodes = {'rol': 0, 'ror': 1, 'shl': 4, 'shr': 5, 'sar': 7}
cmov_opcodes = {'cmov%s' % cond: bytes([0x0F, 0x40 | opcode]) for (cond, opcode) in conditions.items()}
jump_opcodes = {'j%s' % cond: bytes([0x70 | opcode]) for (cond, opcode) in conditions.items()}
jump_opcodes['jmp'] = b'\xEB'

bmi_opcodes = {
    'crc32':  (b'\xF2', b'\x0F\x38\xF1'), # XXX 8-bit source variant
    'popcnt': (b'\xF3', b'\x0F\xB8'),
    'bsf':    (b'',     b'\x0F\xBC'),
    'tzcnt':  (b'\xF3', b'\x0F\xBC'),
    'bsr':    (b'',     b'\x0F\xBD'),
    'lzcnt':  (b'\xF3', b'\x0F\xBD'),
}
bmi_vex_ndd_opcodes = {
    'blsi':   (0, 2, b'\xF3', 3),
    'blsmsk': (0, 2, b'\xF3', 2),
    'blsr':   (0, 2, b'\xF3', 1),
}
bmi_vex_opcodes = {
    'andn':   (0, 2, b'\xF2'),
    'bextr':  (0, 2, b'\xF7'),
    'bzhi':   (0, 2, b'\xF5'),
    'pdep':   (3, 2, b'\xF5'),
    'pext':   (2, 2, b'\xF5'),
    'sarx':   (2, 2, b'\xF7'),
    'shlx':   (1, 2, b'\xF7'),
    'shrx':   (3, 2, b'\xF7'),
}

sse_avx_opcodes = {
    'cvtdq2pd':        (b'\xF3', b'\x0F',     b'\xE6', 1), # XXX ymm variant has mixed xmm/ymm args
    'cvtdq2ps':        (b'',     b'\x0F',     b'\x5B', 1),
    'cvtpd2dq':        (b'\xF2', b'\x0F',     b'\xE6', 1), # XXX ymm variant has mixed xmm/ymm args
    'cvtpd2ps':        (b'\x66', b'\x0F',     b'\x5A', 1), # XXX ymm variant has mixed xmm/ymm args
    'cvtps2dq':        (b'\x66', b'\x0F',     b'\x5B', 1),
    'cvtps2pd':        (b'',     b'\x0F',     b'\x5A', 1), # XXX ymm variant has mixed xmm/ymm args

    'addpd':           (b'\x66', b'\x0F',     b'\x58', 0),
    'addps':           (b'',     b'\x0F',     b'\x58', 0),
    'addsd':           (b'\xF2', b'\x0F',     b'\x58', 0), # XXX prohibit YMM register version
    'addss':           (b'\xF3', b'\x0F',     b'\x58', 0), # XXX prohibit YMM register version
    'addsubpd':        (b'\x66', b'\x0F',     b'\xD0', 0),
    'addsubps':        (b'\xF2', b'\x0F',     b'\xD0', 0),
    'aesdec':          (b'\x66', b'\x0F\x38', b'\xDE', 0), # XXX prohibit YMM register version
    'aesdeclast':      (b'\x66', b'\x0F\x38', b'\xDF', 0), # XXX prohibit YMM register version
    'aesenc':          (b'\x66', b'\x0F\x38', b'\xDC', 0), # XXX prohibit YMM register version
    'aesenclast':      (b'\x66', b'\x0F\x38', b'\xDD', 0), # XXX prohibit YMM register version
    'aesimc':          (b'\x66', b'\x0F\x38', b'\xDB', 1), # XXX prohibit YMM register version
    'aeskeygenassist': (b'\x66', b'\x0F\x3A', b'\xDF', 3), # XXX prohibit YMM register version
    'andpd':           (b'\x66', b'\x0F',     b'\x54', 0),
    'andps':           (b'',     b'\x0F',     b'\x54', 0),
    'andnpd':          (b'\x66', b'\x0F',     b'\x55', 0),
    'andnps':          (b'',     b'\x0F',     b'\x55', 0),
    'blendpd':         (b'\x66', b'\x0F\x3A', b'\x0D', 2),
    'blendps':         (b'\x66', b'\x0F\x3A', b'\x0C', 2),
    'cmppd':           (b'\x66', b'\x0F',     b'\xC2', 2),
    'cmpps':           (b'',     b'\x0F',     b'\xC2', 2),
    'cmpsd':           (b'\xF2', b'\x0F',     b'\xC2', 2),
    'cmpss':           (b'\xF3', b'\x0F',     b'\xC2', 2),
    'comisd':          (b'\x66', b'\x0F',     b'\x2F', 0), # XXX prohibit YMM register version
    'comiss':          (b'',     b'\x0F',     b'\x2F', 0), # XXX prohibit YMM register version
    'divpd':           (b'\x66', b'\x0F',     b'\x5E', 0),
    'divps':           (b'',     b'\x0F',     b'\x5E', 0),
    'divsd':           (b'\xF2', b'\x0F',     b'\x5E', 0), # XXX prohibit YMM register version
    'divss':           (b'\xF3', b'\x0F',     b'\x5E', 0), # XXX prohibit YMM register version
    'dppd':            (b'\x66', b'\x0F\x3A', b'\x41', 2), # XXX prohibit YMM register version
    'dpps':            (b'\x66', b'\x0F\x3A', b'\x40', 2),
    'haddpd':          (b'\x66', b'\x0F',     b'\x7C', 0),
    'haddps':          (b'\xF2', b'\x0F',     b'\x7C', 0),
    'hsubpd':          (b'\x66', b'\x0F',     b'\x7D', 0),
    'hsubps':          (b'\xF2', b'\x0F',     b'\x7D', 0),
    'insertps':        (b'\x66', b'\x0F\x3A', b'\x21', 2), # XXX prohibit YMM register version
    'maxpd':           (b'\x66', b'\x0F',     b'\x5F', 0),
    'maxps':           (b'',     b'\x0F',     b'\x5F', 0),
    'maxsd':           (b'\xF2', b'\x0F',     b'\x5F', 0), # XXX prohibit YMM register version
    'maxss':           (b'\xF3', b'\x0F',     b'\x5F', 0), # XXX prohibit YMM register version
    'minpd':           (b'\x66', b'\x0F',     b'\x5D', 0),
    'minps':           (b'',     b'\x0F',     b'\x5D', 0),
    'minsd':           (b'\xF2', b'\x0F',     b'\x5D', 0), # XXX prohibit YMM register version
    'minss':           (b'\xF3', b'\x0F',     b'\x5D', 0), # XXX prohibit YMM register version
    'movshdup':        (b'\xF3', b'\x0F',     b'\x16', 1),
    'movsldup':        (b'\xF3', b'\x0F',     b'\x12', 1),
    'mpsadbw':         (b'\x66', b'\x0F\x3A', b'\x42', 2),
    'mulpd':           (b'\x66', b'\x0F',     b'\x59', 0),
    'mulps':           (b'',     b'\x0F',     b'\x59', 0),
    'mulsd':           (b'\xF2', b'\x0F',     b'\x59', 0), # XXX prohibit YMM register version
    'mulss':           (b'\xF3', b'\x0F',     b'\x59', 0), # XXX prohibit YMM register version
    'orpd':            (b'\x66', b'\x0F',     b'\x56', 0),
    'orps':            (b'',     b'\x0F',     b'\x56', 0),
    'pabsb':           (b'\x66', b'\x0F\x38', b'\x1C', 1),
    'pabsw':           (b'\x66', b'\x0F\x38', b'\x1D', 1),
    'pabsd':           (b'\x66', b'\x0F\x38', b'\x1E', 1),
    'packsswb':        (b'\x66', b'\x0F',     b'\x63', 0),
    'packssdw':        (b'\x66', b'\x0F',     b'\x6B', 0),
    'packuswb':        (b'\x66', b'\x0F',     b'\x67', 0),
    'packusdw':        (b'\x66', b'\x0F\x38', b'\x2B', 0),
    'paddb':           (b'\x66', b'\x0F',     b'\xFC', 0),
    'paddw':           (b'\x66', b'\x0F',     b'\xFD', 0),
    'paddd':           (b'\x66', b'\x0F',     b'\xFE', 0),
    'paddq':           (b'\x66', b'\x0F',     b'\xD4', 0),
    'paddsb':          (b'\x66', b'\x0F',     b'\xEC', 0),
    'paddsw':          (b'\x66', b'\x0F',     b'\xED', 0),
    'paddusb':         (b'\x66', b'\x0F',     b'\xDC', 0),
    'paddusw':         (b'\x66', b'\x0F',     b'\xDD', 0),
    'palignr':         (b'\x66', b'\x0F\x3A', b'\x0F', 3),
    'pand':            (b'\x66', b'\x0F',     b'\xDB', 0),
    'pandn':           (b'\x66', b'\x0F',     b'\xDF', 0),
    'pavgb':           (b'\x66', b'\x0F',     b'\xE0', 0),
    'pavgw':           (b'\x66', b'\x0F',     b'\xE3', 0),
    'pblendw':         (b'\x66', b'\x0F\x3A', b'\x0E', 3),
    'pclmulqdq':       (b'\x66', b'\x0F\x3A', b'\x44', 2),
    'pcmpeqb':         (b'\x66', b'\x0F',     b'\x74', 0),
    'pcmpeqw':         (b'\x66', b'\x0F',     b'\x75', 0),
    'pcmpeqd':         (b'\x66', b'\x0F',     b'\x76', 0),
    'pcmpeqq':         (b'\x66', b'\x0F\x38', b'\x29', 0),
    'pcmpestri':       (b'\x66', b'\x0F\x3A', b'\x61', 3),
    'pcmpestrm':       (b'\x66', b'\x0F\x3A', b'\x60', 3),
    'pcmpgtb':         (b'\x66', b'\x0F',     b'\x64', 0),
    'pcmpgtw':         (b'\x66', b'\x0F',     b'\x65', 0),
    'pcmpgtd':         (b'\x66', b'\x0F',     b'\x66', 0),
    'pcmpgtq':         (b'\x66', b'\x0F\x38', b'\x37', 0),
    'pcmpistri':       (b'\x66', b'\x0F\x3A', b'\x63', 3),
    'pcmpistrm':       (b'\x66', b'\x0F\x3A', b'\x62', 3),
    # XXX pextrb/pextrw/pextrd/pextrq
    'phaddw':          (b'\x66', b'\x0F\x38', b'\x01', 0),
    'phaddd':          (b'\x66', b'\x0F\x38', b'\x02', 0),
    'phaddsw':         (b'\x66', b'\x0F\x38', b'\x03', 0),
    'phminposuw':      (b'\x66', b'\x0F\x38', b'\x41', 1), # XXX prohibit YMM register version
    'phsubw':          (b'\x66', b'\x0F\x38', b'\x05', 0),
    'phsubd':          (b'\x66', b'\x0F\x38', b'\x06', 0),
    'phsubsw':         (b'\x66', b'\x0F\x38', b'\x07', 0),
    # XXX pinsrb/pinsrw/pinsrd/pinsrq
    'pmaddubsw':       (b'\x66', b'\x0F\x38', b'\x04', 0),
    'pmaddwd':         (b'\x66', b'\x0F',     b'\xF5', 0),
    'pmaxsb':          (b'\x66', b'\x0F\x38', b'\x3C', 0),
    'pmaxsw':          (b'\x66', b'\x0F',     b'\xEE', 0),
    'pmaxsd':          (b'\x66', b'\x0F\x38', b'\x3D', 0),
    'pmaxub':          (b'\x66', b'\x0F',     b'\xDE', 0),
    'pmaxuw':          (b'\x66', b'\x0F\x38', b'\x3E', 0),
    'pmaxud':          (b'\x66', b'\x0F\x38', b'\x3F', 0),
    'pminsb':          (b'\x66', b'\x0F\x38', b'\x38', 0),
    'pminsw':          (b'\x66', b'\x0F',     b'\xEA', 0),
    'pminsd':          (b'\x66', b'\x0F\x38', b'\x39', 0),
    'pminub':          (b'\x66', b'\x0F',     b'\xDA', 0),
    'pminuw':          (b'\x66', b'\x0F\x38', b'\x3A', 0),
    'pminud':          (b'\x66', b'\x0F\x38', b'\x3B', 0),
    'pmovsxbw':        (b'\x66', b'\x0F\x38', b'\x20', 1), # XXX ymm variant has mixed xmm/ymm args
    'pmovsxbd':        (b'\x66', b'\x0F\x38', b'\x21', 1), # XXX ymm variant has mixed xmm/ymm args
    'pmovsxbq':        (b'\x66', b'\x0F\x38', b'\x22', 1), # XXX ymm variant has mixed xmm/ymm args
    'pmovsxwd':        (b'\x66', b'\x0F\x38', b'\x23', 1), # XXX ymm variant has mixed xmm/ymm args
    'pmovsxwq':        (b'\x66', b'\x0F\x38', b'\x24', 1), # XXX ymm variant has mixed xmm/ymm args
    'pmovsxdq':        (b'\x66', b'\x0F\x38', b'\x25', 1), # XXX ymm variant has mixed xmm/ymm args
    'pmovzxbw':        (b'\x66', b'\x0F\x38', b'\x30', 1), # XXX ymm variant has mixed xmm/ymm args
    'pmovzxbd':        (b'\x66', b'\x0F\x38', b'\x31', 1), # XXX ymm variant has mixed xmm/ymm args
    'pmovzxbq':        (b'\x66', b'\x0F\x38', b'\x32', 1), # XXX ymm variant has mixed xmm/ymm args
    'pmovzxwd':        (b'\x66', b'\x0F\x38', b'\x33', 1), # XXX ymm variant has mixed xmm/ymm args
    'pmovzxwq':        (b'\x66', b'\x0F\x38', b'\x34', 1), # XXX ymm variant has mixed xmm/ymm args
    'pmovzxdq':        (b'\x66', b'\x0F\x38', b'\x35', 1), # XXX ymm variant has mixed xmm/ymm args
    'pmuldq':          (b'\x66', b'\x0F\x38', b'\x28', 0),
    'pmulhrsw':        (b'\x66', b'\x0F\x38', b'\x0B', 0),
    'pmulhuw':         (b'\x66', b'\x0F',     b'\xE4', 0),
    'pmulhw':          (b'\x66', b'\x0F',     b'\xE5', 0),
    'pmulld':          (b'\x66', b'\x0F\x38', b'\x40', 0),
    'pmullw':          (b'\x66', b'\x0F',     b'\xD5', 0),
    'pmuludq':         (b'\x66', b'\x0F',     b'\xF4', 0),
    'por':             (b'\x66', b'\x0F',     b'\xEB', 0),
    'psadbw':          (b'\x66', b'\x0F',     b'\xF6', 0),
    'pshufb':          (b'\x66', b'\x0F\x38', b'\x00', 0),
    'pshufd':          (b'\x66', b'\x0F',     b'\x70', 3),
    'pshufhw':         (b'\xF3', b'\x0F',     b'\x70', 3),
    'pshuflw':         (b'\xF2', b'\x0F',     b'\x70', 3),
    'psignb':          (b'\x66', b'\x0F\x38', b'\x08', 1),
    'psignw':          (b'\x66', b'\x0F\x38', b'\x09', 1),
    'psignd':          (b'\x66', b'\x0F\x38', b'\x0A', 1),
    # XXX psllw/pslld/psllq/pslldq by immediate
    'psllw':           (b'\x66', b'\x0F',     b'\xF1', 0), # XXX ymm variant has mixed xmm/ymm args
    'pslld':           (b'\x66', b'\x0F',     b'\xF2', 0), # XXX ymm variant has mixed xmm/ymm args
    'psllq':           (b'\x66', b'\x0F',     b'\xF3', 0), # XXX ymm variant has mixed xmm/ymm args
    # XXX psraw/psrad by immediate
    'psraw':           (b'\x66', b'\x0F',     b'\xE1', 0), # XXX ymm variant has mixed xmm/ymm args
    'psrad':           (b'\x66', b'\x0F',     b'\xE2', 0), # XXX ymm variant has mixed xmm/ymm args
    # XXX psrlw/psrld/psrlq/psrldq by immediate
    'psrlw':           (b'\x66', b'\x0F',     b'\xD1', 0), # XXX ymm variant has mixed xmm/ymm args
    'psrld':           (b'\x66', b'\x0F',     b'\xD2', 0), # XXX ymm variant has mixed xmm/ymm args
    'psrlq':           (b'\x66', b'\x0F',     b'\xD3', 0), # XXX ymm variant has mixed xmm/ymm args
    'psubb':           (b'\x66', b'\x0F',     b'\xF8', 0),
    'psubw':           (b'\x66', b'\x0F',     b'\xF9', 0),
    'psubd':           (b'\x66', b'\x0F',     b'\xFA', 0),
    'psubq':           (b'\x66', b'\x0F',     b'\xFB', 0),
    'psubsb':          (b'\x66', b'\x0F',     b'\xE8', 0),
    'psubsw':          (b'\x66', b'\x0F',     b'\xE9', 0),
    'psubusb':         (b'\x66', b'\x0F',     b'\xD8', 0),
    'psubusw':         (b'\x66', b'\x0F',     b'\xD9', 0),
    'ptest':           (b'\x66', b'\x0F\x38', b'\x17', 1),
    'punpckhbw':       (b'\x66', b'\x0F',     b'\x68', 0),
    'punpckhwd':       (b'\x66', b'\x0F',     b'\x69', 0),
    'punpckhdq':       (b'\x66', b'\x0F',     b'\x6A', 0),
    'punpckhqdq':      (b'\x66', b'\x0F',     b'\x6D', 0),
    'punpcklbw':       (b'\x66', b'\x0F',     b'\x60', 0),
    'punpcklwd':       (b'\x66', b'\x0F',     b'\x61', 0),
    'punpckldq':       (b'\x66', b'\x0F',     b'\x62', 0),
    'punpcklqdq':      (b'\x66', b'\x0F',     b'\x6C', 0),
    'pxor':            (b'\x66', b'\x0F',     b'\xEF', 0),
    'rcpps':           (b'',     b'\x0F',     b'\x53', 1),
    'rcpss':           (b'\xF3', b'\x0F',     b'\x53', 1), # XXX prohibit YMM register version
    'roundpd':         (b'\x66', b'\x0F\x3A', b'\x09', 3),
    'roundps':         (b'\x66', b'\x0F\x3A', b'\x08', 3),
    'roundsd':         (b'\x66', b'\x0F\x3A', b'\x0B', 3), # XXX prohibit YMM register version
    'roundss':         (b'\x66', b'\x0F\x3A', b'\x0A', 3), # XXX prohibit YMM register version
    'rsqrtps':         (b'',     b'\x0F',     b'\x52', 1),
    'rsqrtss':         (b'\xF3', b'\x0F',     b'\x52', 1), # XXX prohibit YMM register version
    'shufpd':          (b'\x66', b'\x0F',     b'\xC6', 3),
    'shufps':          (b'',     b'\x0F',     b'\xC6', 3),
    'sqrtpd':          (b'\x66', b'\x0F',     b'\x51', 1),
    'sqrtps':          (b'',     b'\x0F',     b'\x51', 1),
    'sqrtsd':          (b'\xF2', b'\x0F',     b'\x51', 1), # XXX prohibit YMM register version
    'sqrtss':          (b'\xF3', b'\x0F',     b'\x51', 1), # XXX prohibit YMM register version
    'subps':           (b'',     b'\x0F',     b'\x5C', 0),
    'subpd':           (b'\x66', b'\x0F',     b'\x5C', 0),
    'subss':           (b'\xF3', b'\x0F',     b'\x5C', 0), # XXX prohibit YMM register version
    'subsd':           (b'\xF2', b'\x0F',     b'\x5C', 0), # XXX prohibit YMM register version
    'ucomisd':         (b'\x66', b'\x0F',     b'\x2E', 0), # XXX prohibit YMM register version
    'ucomiss':         (b'',     b'\x0F',     b'\x2E', 0), # XXX prohibit YMM register version
    'unpckhpd':        (b'\x66', b'\x0F',     b'\x15', 0),
    'unpckhps':        (b'',     b'\x0F',     b'\x15', 0),
    'unpcklpd':        (b'\x66', b'\x0F',     b'\x14', 0),
    'unpcklps':        (b'',     b'\x0F',     b'\x14', 0),
    'xorpd':           (b'\x66', b'\x0F',     b'\x57', 0),
    'xorps':           (b'',     b'\x0F',     b'\x57', 0),

    'cvtsd2ss':        (b'\xF2', b'\x0F',     b'\x5A', 1),
    'cvtss2sd':        (b'\xF3', b'\x0F',     b'\x5A', 1),

    'movapd':          (b'\x66', b'\x0F',     b'\x28', 1),
    'movaps':          (b'',     b'\x0F',     b'\x28', 1),
    'storeapd':        (b'\x66', b'\x0F',     b'\x29', 1),
    'storeaps':        (b'',     b'\x0F',     b'\x29', 1),
    'movsd':           (b'\xF2', b'\x0F',     b'\x10', 0),
    'movss':           (b'\xF3', b'\x0F',     b'\x10', 0),
    'storesd':         (b'\xF2', b'\x0F',     b'\x11', 0),
    'storess':         (b'\xF3', b'\x0F',     b'\x11', 0),
    'movupd':          (b'\x66', b'\x0F',     b'\x10', 1),
    'movups':          (b'',     b'\x0F',     b'\x10', 1),
    'storeupd':        (b'\x66', b'\x0F',     b'\x11', 1),
    'storeups':        (b'',     b'\x0F',     b'\x11', 1),
    'movdqa':          (b'\x66', b'\x0F',     b'\x6F', 1),
    'storedqa':        (b'\x66', b'\x0F',     b'\x7F', 1),
    'movdqu':          (b'\xF3', b'\x0F',     b'\x6F', 1),
    'storedqu':        (b'\xF3', b'\x0F',     b'\x7F', 1),
}

sse_compare_functions = {'eq': 0, 'lt': 1, 'le': 2, 'unord': 3, 'neq': 4, 'nlt': 5, 'nle': 6, 'ord': 7}
sse_compare_aliases = {}
for suffix in ['ps', 'pd', 'ss', 'sd']:
    sse_compare_aliases.update({'cmp%s%s' % (name, suffix): ('cmp%s' % suffix, imm) for (name, imm) in sse_compare_functions.items()})
    sse_compare_aliases.update({'vcmp%s%s' % (name, suffix): ('vcmp%s' % suffix, imm) for (name, imm) in sse_compare_functions.items()})

sse_opcodes = {
    'blendvpd': (b'\x66', b'\x0F\x38\x15', 0),
    'blendvps': (b'\x66', b'\x0F\x38\x14', 0),
    'pblendvb': (b'\x66', b'\x0F\x38\x10', 0),
}
avx_opcodes = {
    #                w  p  m  opcode   template
    'vblendvpd':    (0, 1, 3, b'\x4B', 5),
    'vblendvps':    (0, 1, 3, b'\x4A', 5),
    'vbroadcastss': (0, 1, 2, b'\x18', 1),
    'vcvtph2ps':    (0, 1, 2, b'\x13', 1), # XXX ymm variant has mixed xmm/ymm args
    'vcvtps2ph':    (0, 1, 3, b'\x1D', 3), # XXX ymm variant has mixed xmm/ymm args
    'vinsertf128':  (0, 1, 3, b'\x18', 4),
    'vmaskmovps':   (0, 1, 2, b'\x2E', 5),
    'vpblendvb':    (0, 1, 3, b'\x4C', 5),
    'vpsllvd':      (0, 1, 2, b'\x47', 0),
    'vpsllvq':      (1, 1, 2, b'\x47', 0),
    'vpsravd':      (0, 1, 2, b'\x46', 0),
    'vpsrlvd':      (0, 1, 2, b'\x45', 0),
    'vpsrlvq':      (1, 1, 2, b'\x45', 0),
    'vtestpd':      (0, 1, 2, b'\x0F', 1),
    'vtestps':      (0, 1, 2, b'\x0E', 1),

    'vfmadd132pd':  (1, 1, 2, b'\x98', 0),
    'vfmadd132ps':  (0, 1, 2, b'\x98', 0),
    'vfmadd213pd':  (1, 1, 2, b'\xA8', 0),
    'vfmadd213ps':  (0, 1, 2, b'\xA8', 0),
    'vfmadd231pd':  (1, 1, 2, b'\xB8', 0),
    'vfmadd231ps':  (0, 1, 2, b'\xB8', 0),
    'vfmadd132sd':  (1, 1, 2, b'\x99', 0),
    'vfmadd132ss':  (0, 1, 2, b'\x99', 0),
    'vfmadd213sd':  (1, 1, 2, b'\xA9', 0),
    'vfmadd213ss':  (0, 1, 2, b'\xA9', 0),
    'vfmadd231sd':  (1, 1, 2, b'\xB9', 0),
    'vfmadd231ss':  (0, 1, 2, b'\xB9', 0),

    'vfnmadd132pd': (1, 1, 2, b'\x9C', 0),
    'vfnmadd132ps': (0, 1, 2, b'\x9C', 0),
    'vfnmadd213pd': (1, 1, 2, b'\xAC', 0),
    'vfnmadd213ps': (0, 1, 2, b'\xAC', 0),
    'vfnmadd231pd': (1, 1, 2, b'\xBC', 0),
    'vfnmadd231ps': (0, 1, 2, b'\xBC', 0),
    'vfnmadd132sd': (1, 1, 2, b'\x9D', 0),
    'vfnmadd132ss': (0, 1, 2, b'\x9D', 0),
    'vfnmadd213sd': (1, 1, 2, b'\xAD', 0),
    'vfnmadd213ss': (0, 1, 2, b'\xAD', 0),
    'vfnmadd231sd': (1, 1, 2, b'\xBD', 0),
    'vfnmadd231ss': (0, 1, 2, b'\xBD', 0),

    'vfmsub132pd':  (1, 1, 2, b'\x9A', 0),
    'vfmsub132ps':  (0, 1, 2, b'\x9A', 0),
    'vfmsub213pd':  (1, 1, 2, b'\xAA', 0),
    'vfmsub213ps':  (0, 1, 2, b'\xAA', 0),
    'vfmsub231pd':  (1, 1, 2, b'\xBA', 0),
    'vfmsub231ps':  (0, 1, 2, b'\xBA', 0),
    'vfmsub132sd':  (1, 1, 2, b'\x9B', 0),
    'vfmsub132ss':  (0, 1, 2, b'\x9B', 0),
    'vfmsub213sd':  (1, 1, 2, b'\xAB', 0),
    'vfmsub213ss':  (0, 1, 2, b'\xAB', 0),
    'vfmsub231sd':  (1, 1, 2, b'\xBB', 0),
    'vfmsub231ss':  (0, 1, 2, b'\xBB', 0),

    'vfnmsub132pd': (1, 1, 2, b'\x9E', 0),
    'vfnmsub132ps': (0, 1, 2, b'\x9E', 0),
    'vfnmsub213pd': (1, 1, 2, b'\xAE', 0),
    'vfnmsub213ps': (0, 1, 2, b'\xAE', 0),
    'vfnmsub231pd': (1, 1, 2, b'\xBE', 0),
    'vfnmsub231ps': (0, 1, 2, b'\xBE', 0),
    'vfnmsub132sd': (1, 1, 2, b'\x9F', 0),
    'vfnmsub132ss': (0, 1, 2, b'\x9F', 0),
    'vfnmsub213sd': (1, 1, 2, b'\xAF', 0),
    'vfnmsub213ss': (0, 1, 2, b'\xAF', 0),
    'vfnmsub231sd': (1, 1, 2, b'\xBF', 0),
    'vfnmsub231ss': (0, 1, 2, b'\xBF', 0),

    'vfmaddsub132pd': (1, 1, 2, b'\x96', 0),
    'vfmaddsub132ps': (0, 1, 2, b'\x96', 0),
    'vfmaddsub213pd': (1, 1, 2, b'\xA6', 0),
    'vfmaddsub213ps': (0, 1, 2, b'\xA6', 0),
    'vfmaddsub231pd': (1, 1, 2, b'\xB6', 0),
    'vfmaddsub231ps': (0, 1, 2, b'\xB6', 0),

    'vfmsubadd132pd': (1, 1, 2, b'\x97', 0),
    'vfmsubadd132ps': (0, 1, 2, b'\x97', 0),
    'vfmsubadd213pd': (1, 1, 2, b'\xA7', 0),
    'vfmsubadd213ps': (0, 1, 2, b'\xA7', 0),
    'vfmsubadd231pd': (1, 1, 2, b'\xB7', 0),
    'vfmsubadd231ps': (0, 1, 2, b'\xB7', 0),
}

avx_p_table = {b'': 0, b'\x66': 1, b'\xF3': 2, b'\xF2': 3}
avx_m_table = {b'\x0F': 1, b'\x0F\x38': 2, b'\x0F\x3A': 3}
for (name, (prefix, opcode_prefix, opcode, template)) in sse_avx_opcodes.items():
    sse_opcodes[name] = (prefix, opcode_prefix + opcode, template)
    avx_opcodes['v' + name] = (0, avx_p_table[prefix], avx_m_table[opcode_prefix], opcode, template)

def rex(w, r, x, b, force=0):
    value = (w << 3) | ((r & 8) >> 1) | ((x & 8) >> 2) | ((b & 8) >> 3)
    return bytes([0x40 | value]) if value or force else b''

def rex_addr(w, r, a):
    return rex(w, r, a.index, a.base)

def vex(w, r, x, b, p, m, l, v=0):
    r &= 8
    x &= 8
    b &= 8
    if x or b or m != 1 or w:
        return bytes([0xC4, ((r ^ 8) << 4) | ((x ^ 8) << 3) | ((b ^ 8) << 2) | m,
                     (w << 7) | ((v ^ 15) << 3) | (l << 2) | p])
    else:
        return bytes([0xC5, ((r ^ 8) << 4) | ((v ^ 15) << 3) | (l << 2) | p])

def mod_rm_reg(reg, rm):
    return bytes([0xC0 | ((reg & 7) << 3) | (rm & 7)])

log_scale_table = {1: 0, 2: 1, 4: 2, 8: 3}

def mod_rm_addr(reg, a):
    if a.scale == 0:
        assert a.index == 0 # if no scale, must have no index
        if a.base == 'rip':
            return bytes([((reg & 7) << 3) | 5]) + struct.pack('<i', a.disp)
        elif (a.base & 7) == 4: # RSP/R12 base must be encoded with SIB
            if not a.disp:
                return bytes([((reg & 7) << 3) | 4, 0x24])
            elif -128 <= a.disp <= 127:
                return bytes([0x40 | ((reg & 7) << 3) | 4, 0x24]) + struct.pack('<b', a.disp)
            else:
                return bytes([0x80 | ((reg & 7) << 3) | 4, 0x24]) + struct.pack('<i', a.disp)
        else:
            if not a.disp and (a.base & 7) != 5: # RBP/R13 base must be encoded with at least a disp8
                return bytes([((reg & 7) << 3) | (a.base & 7)])
            elif -128 <= a.disp <= 127:
                return bytes([0x40 | ((reg & 7) << 3) | (a.base & 7)]) + struct.pack('<b', a.disp)
            else:
                return bytes([0x80 | ((reg & 7) << 3) | (a.base & 7)]) + struct.pack('<i', a.disp)
    else:
        assert a.base != 'rip' # base cannot be RIP with an index
        assert a.index != 4 # index can never be the stack pointer
        log_scale = log_scale_table[a.scale]
        if not a.disp and (a.base & 7) != 5: # RBP/R13 base must be encoded with at least a disp8
            return bytes([((reg & 7) << 3) | 4, (log_scale << 6) | ((a.index & 7) << 3) | (a.base & 7)])
        elif -128 <= a.disp <= 127:
            return bytes([0x40 | ((reg & 7) << 3) | 4, (log_scale << 6) | ((a.index & 7) << 3) | (a.base & 7)]) + struct.pack('<b', a.disp)
        else:
            return bytes([0x80 | ((reg & 7) << 3) | 4, (log_scale << 6) | ((a.index & 7) << 3) | (a.base & 7)]) + struct.pack('<i', a.disp)

tokens = [
    ('ID', r'[A-Za-z_][A-Za-z0-9_]*'),
    ('NUMBER', r'0(x[A-Fa-f0-9_]+)?|[1-9][0-9]*'),
    ('SYMBOL', r'[\*+\-,\[\]]'),
    ('SKIP', r'[ \t]'),
]
r = re.compile('|'.join('(?P<%s>%s)' % pair for pair in tokens)).match

class Address:
    def __init__(self, base, scale, index, disp):
        self.base = base
        self.scale = scale
        self.index = index
        self.disp = disp

class RelLabel:
    def __init__(self, code_offset):
        self.code_offset = code_offset

class Parser:
    def __init__(self):
        self.globals = set()
        self.labels = []
        self.code = b''
        self.macros = {}
        self.defines = {}
        self.cur_macro_args = None

    def find_label_offset(self, label):
        for (name, offset) in self.labels:
            if name == label:
                return offset
        raise RuntimeError("could not find label '%s'" % label)

    def line_to_code(self, line):
        if line.startswith('global '):
            self.globals.add(line[7:])
            return
        if line == 'segment code':
            return # XXX skip
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
                while val in self.defines:
                    val = self.defines[val]
                if typ == 'NUMBER':
                    val = int(val, 0)
                tokens.append(val)
            pos = mo.end()
            mo = r(line, pos)
        if pos != len(line):
            raise RuntimeError('Unexpected character %r' % line[pos])

        if tokens[0] in self.macros:
            (macro_lines, n_args) = self.macros[tokens[0]]
            if n_args == 0:
                assert len(tokens) == 1
            else:
                assert len(tokens) == 2*n_args
                for i in range(2, 2*n_args, 2):
                    assert tokens[i] == ','
            for macro_line in macro_lines:
                for i in range(0, n_args):
                    macro_line = macro_line.replace('%%%d' % (i+1), tokens[2*i+1])
                self.line_to_code(macro_line)
            return

        # hacky constant folding -- would be easier if we generated a better parse tree
        if '*' in tokens:
            i = tokens.index('*')
            if isinstance(tokens[i-1], int) and isinstance(tokens[i+1], int):
                tokens[i-1:i+2] = [tokens[i-1] * tokens[i+1]]

        # parse address expressions
        if '[' in tokens:
            i = tokens.index('[')
            if tokens[i+2] == ']':
                tokens[i:i+3] = [Address(reg64_nums[tokens[i+1]], 0, 0, 0)]
            elif tokens[i+3] == ']':
                assert tokens[i+1] == 'rel'
                tokens[i:i+4] = [RelLabel(self.find_label_offset(tokens[i+2]))]
            elif tokens[i+4] == ']':
                if tokens[i+2] == '+':
                    if isinstance(tokens[i+3], int):
                        tokens[i:i+5] = [Address(reg64_nums[tokens[i+1]], 0, 0, tokens[i+3])]
                    else:
                        tokens[i:i+5] = [Address(reg64_nums[tokens[i+1]], 1, reg64_nums[tokens[i+3]], 0)]
                else:
                    assert tokens[i+2] == '-'
                    tokens[i:i+5] = [Address(reg64_nums[tokens[i+1]], 0, 0, -tokens[i+3])]
            elif tokens[i+6] == ']':
                assert tokens[i+2] == '+'
                assert tokens[i+3] in {1, 2, 4, 8}
                assert tokens[i+4] == '*'
                tokens[i:i+7] = [Address(reg64_nums[tokens[i+1]], tokens[i+3], reg64_nums[tokens[i+5]], 0)]
            elif tokens[i+8] == ']':
                assert tokens[i+2] == '+'
                assert tokens[i+3] in {1, 2, 4, 8}
                assert tokens[i+4] == '*'
                assert tokens[i+6] == '+'
                assert isinstance(tokens[i+7], int)
                tokens[i:i+9] = [Address(reg64_nums[tokens[i+1]], tokens[i+3], reg64_nums[tokens[i+5]], tokens[i+7])]

        # name and comma-separated args
        name = tokens[0]
        if len(tokens) == 1:
            args = []
        else:
            assert not len(tokens) & 1
            for i in range(2, len(tokens), 2):
                assert tokens[i] == ','
            args = tokens[1::2]

        # convert stores to a different opcode name so we can look them up more easily
        if name in {'movapd', 'movaps', 'vmovapd', 'vmovaps',
                    'movsd', 'movss', 'vmovss', 'vmovsd',
                    'movupd', 'movups', 'vmovupd', 'vmovups',
                    'movdqa', 'vmovdqa', 'movdqu', 'vmovdqu', 'mov'} and args and isinstance(args[0], Address):
            assert len(args) == 2
            name = name.replace('mov', 'store')
            args = [args[1], args[0]]

        # this is sort of like a store instruction also
        if name in {'vcvtps2ph'}:
            assert len(args) == 3
            args = [args[1], args[0], args[2]]

        if name in trivial_opcodes and not args:
            self.code += trivial_opcodes[name]
            return

        if name == 'lea':
            assert len(args) == 2
            assert isinstance(args[1], RelLabel)
            disp = args[1].code_offset - (len(self.code) + 7)
            r_dst = reg64_nums[args[0]]
            self.code += rex(1, r_dst, 0, 0) + b'\x8D' + mod_rm_addr(r_dst, Address('rip', 0, 0, disp))
            return

        if name == 'mov':
            assert len(args) == 2
            w = args[0] in reg64_nums
            r_dst = reg64_nums[args[0]] if w else reg32_nums[args[0]]
            if isinstance(args[1], int):
                if w:
                    self.code += rex(w, 0, 0, r_dst) + bytes([0xB8 | (r_dst & 7)]) + struct.pack('<q', args[1])
                else:
                    self.code += rex(w, 0, 0, r_dst) + bytes([0xB8 | (r_dst & 7)]) + struct.pack('<i', args[1])
            elif isinstance(args[1], Address):
                self.code += rex_addr(w, r_dst, args[1]) + b'\x8B' + mod_rm_addr(r_dst, args[1])
            else:
                r_src = reg64_nums[args[1]] if w else reg32_nums[args[1]]
                self.code += rex(w, r_src, 0, r_dst) + b'\x89' + mod_rm_reg(r_src, r_dst)
            return
        if name == 'store':
            assert len(args) == 2
            w = args[0] in reg64_nums
            r_src = reg64_nums[args[0]] if w else reg32_nums[args[0]]
            self.code += rex_addr(w, r_src, args[1]) + b'\x89' + mod_rm_addr(r_src, args[1])
            return

        if name in basic_opcodes:
            assert len(args) == 2
            opcode = basic_opcodes[name]
            if isinstance(args[0], Address):
                w = args[1] in reg64_nums
                r_src = reg64_nums[args[1]] if w else reg32_nums[args[1]]
                opcode = bytes([1 | (opcode << 3)])
                self.code += rex_addr(w, r_src, args[0]) + opcode + mod_rm_addr(r_src, args[0])
            else:
                w = args[0] in reg64_nums
                r_dst = reg64_nums[args[0]] if w else reg32_nums[args[0]]
                if isinstance(args[1], int):
                    if -128 <= args[1] <= 127:
                        self.code += rex(w, 0, 0, r_dst) + b'\x83' + mod_rm_reg(opcode, r_dst) + struct.pack('<b', args[1])
                    else:
                        self.code += rex(w, 0, 0, r_dst) + b'\x81' + mod_rm_reg(opcode, r_dst) + struct.pack('<i', args[1])
                elif isinstance(args[1], Address):
                    opcode = bytes([3 | (opcode << 3)])
                    self.code += rex_addr(w, r_dst, args[1]) + opcode + mod_rm_addr(r_dst, args[1])
                else:
                    r_src = reg64_nums[args[1]] if w else reg32_nums[args[1]]
                    opcode = bytes([1 | (opcode << 3)])
                    self.code += rex(w, r_src, 0, r_dst) + opcode + mod_rm_reg(r_src, r_dst)
            return

        if name == 'test':
            assert len(args) == 2
            w = args[0] in reg64_nums
            r_dst = reg64_nums[args[0]] if w else reg32_nums[args[0]]
            if isinstance(args[1], int):
                if r_dst == 0: # special case saves a byte on AX
                    self.code += rex(w, 0, 0, r_dst) + b'\xA9' + struct.pack('<I', args[1])
                else:
                    self.code += rex(w, 0, 0, r_dst) + b'\xF7' + mod_rm_reg(0, r_dst) + struct.pack('<I', args[1])
            elif isinstance(args[1], Address):
                self.code += rex_addr(w, r_dst, args[1]) + b'\x85' + mod_rm_addr(r_dst, args[1])
            else:
                r_src = reg64_nums[args[1]] if w else reg32_nums[args[1]]
                self.code += rex(w, r_src, 0, r_dst) + b'\x85' + mod_rm_reg(r_src, r_dst)
            return

        if name == 'in':
            assert len(args) == 2
            if args[0] == 'al':
                if args[1] == 'dx':
                    self.code += b'\xEC'
                else:
                    self.code += b'\xE4' + bytes([args[1]])
            else:
                assert args[0] in {'ax', 'eax'}
                if args[0] == 'ax':
                    self.code += b'\x66'
                if args[1] == 'dx':
                    self.code += b'\xED'
                else:
                    self.code += b'\xE5' + bytes([args[1]])
            return
        if name == 'out':
            assert len(args) == 2
            if args[1] == 'al':
                if args[0] == 'dx':
                    self.code += b'\xEE'
                else:
                    self.code += b'\xE6' + bytes([args[0]])
            else:
                assert args[1] in {'ax', 'eax'}
                if args[1] == 'ax':
                    self.code += b'\x66'
                if args[0] == 'dx':
                    self.code += b'\xEF'
                else:
                    self.code += b'\xE7' + bytes([args[0]])
            return
        if name in {'ret', 'retn'}:
            assert len(args) == 1
            self.code += b'\xC2' + struct.pack('<H', args[0])
            return
        if name == 'retf':
            assert len(args) == 1
            self.code += b'\xCA' + struct.pack('<H', args[0])
            return

        if name in cmov_opcodes:
            assert len(args) == 2
            opcode = cmov_opcodes[name]
            w = args[0] in reg64_nums
            r_dst = reg64_nums[args[0]] if w else reg32_nums[args[0]]
            if isinstance(args[1], Address):
                self.code += rex_addr(w, r_dst, args[1]) + opcode + mod_rm_addr(r_dst, args[1])
            else:
                r_src = reg64_nums[args[1]] if w else reg32_nums[args[1]]
                self.code += rex(w, r_dst, 0, r_src) + opcode + mod_rm_reg(r_dst, r_src)
            return

        if name in bmi_opcodes:
            assert len(args) == 2
            (prefix, opcode) = bmi_opcodes[name]
            w = args[0] in reg64_nums
            r_dst = reg64_nums[args[0]] if w else reg32_nums[args[0]]
            if isinstance(args[1], Address):
                self.code += prefix + rex_addr(w, r_dst, args[1]) + opcode + mod_rm_addr(r_dst, args[1])
            else:
                r_src = reg64_nums[args[1]] if w else reg32_nums[args[1]]
                self.code += prefix + rex(w, r_dst, 0, r_src) + opcode + mod_rm_reg(r_dst, r_src)
            return

        # XXX shld/shrd
        if name in shift_opcodes:
            assert len(args) == 2
            if args[1] == 1:
                self.code += b'\xD1' + mod_rm_reg(shift_opcodes[name], reg32_nums[args[0]])
            elif isinstance(args[1], int):
                self.code += b'\xC1' + mod_rm_reg(shift_opcodes[name], reg32_nums[args[0]]) + bytes([args[1]])
            else:
                assert args[1] == 'cl'
                self.code += b'\xD3' + mod_rm_reg(shift_opcodes[name], reg32_nums[args[0]])
            return

        if name in jump_opcodes:
            assert len(args) == 1
            offset = self.find_label_offset(args[0])
            disp = offset - (len(self.code) + 2)
            if -128 <= disp <= 127:
                self.code += jump_opcodes[name] + struct.pack('<b', disp)
            elif name == 'jmp':
                disp = offset - (len(self.code) + 5)
                self.code += b'\xE9' + struct.pack('<i', disp)
            else:
                disp = offset - (len(self.code) + 6)
                self.code += bytes([0x0F, jump_opcodes[name][0] + 0x10]) + struct.pack('<i', disp)
            return

        if name in {'movd', 'movq', 'vmovd', 'vmovq'}:
            assert len(args) == 2
            w = name in {'movq', 'vmovq'}
            if args[0] in xmm_reg_nums:
                r_xmm = xmm_reg_nums[args[0]]
                r_gpr = reg64_nums[args[1]] if w else reg32_nums[args[1]]
                opcode = b'\x6E'
            else:
                r_gpr = reg64_nums[args[0]] if w else reg32_nums[args[0]]
                r_xmm = xmm_reg_nums[args[1]]
                opcode = b'\x7E'
            if name in {'movd', 'movq'}:
                self.code += b'\x66' + rex(w, r_xmm, 0, r_gpr) + b'\x0F' + opcode + mod_rm_reg(r_xmm, r_gpr)
            else:
                self.code += vex(w, r_xmm, 0, r_gpr, 1, 1, 0, 0) + opcode + mod_rm_reg(r_xmm, r_gpr)
            return

        if name in {'blendvpd', 'blendvps', 'pblendvb'}: # just chop off implicit xmm0 arg
            assert len(args) == 3 and args[2] == 'xmm0'
            args = args[0:2] # chop off implicit xmm0
        if name in sse_compare_aliases:
            (name, imm) = sse_compare_aliases[name]
            args.append(imm)

        if name in sse_opcodes:
            (prefix, opcode, template) = sse_opcodes[name]
            if template in {0, 1}:
                assert len(args) == 2
            elif template in {2, 3}:
                assert len(args) == 3
                assert isinstance(args[2], int)
            r_dst = xmm_reg_nums[args[0]]
            if isinstance(args[1], Address):
                self.code += prefix + rex_addr(0, r_dst, args[1]) + opcode + mod_rm_addr(r_dst, args[1])
            else:
                r_src = xmm_reg_nums[args[1]]
                self.code += prefix + rex(0, r_dst, 0, r_src) + opcode + mod_rm_reg(r_dst, r_src)
            if template in {2, 3}:
                self.code += bytes([args[2]])
            return

        if name in {'cvtss2si', 'cvtsd2si'}:
            assert len(args) == 2
            prefix = b'\xF3' if name == 'cvtss2si' else b'\xF2'
            w = args[0] in reg64_nums
            r_dst = reg64_nums[args[0]] if w else reg32_nums[args[0]]
            r_src = xmm_reg_nums[args[1]]
            self.code += prefix + rex(w, r_dst, 0, r_src) + b'\x0F\x2D' + mod_rm_reg(r_dst, r_src)
            return
        if name in {'cvtsi2ss', 'cvtsi2sd'}:
            assert len(args) == 2
            prefix = b'\xF3' if name == 'cvtsi2ss' else b'\xF2'
            w = args[1] in reg64_nums
            r_dst = xmm_reg_nums[args[0]]
            r_src = reg64_nums[args[1]] if w else reg32_nums[args[1]]
            self.code += prefix + rex(w, r_dst, 0, r_src) + b'\x0F\x2A' + mod_rm_reg(r_dst, r_src)
            return
        if name in {'cvttss2si', 'cvttsd2si'}:
            assert len(args) == 2
            prefix = b'\xF3' if name == 'cvttss2si' else b'\xF2'
            w = args[0] in reg64_nums
            r_dst = reg64_nums[args[0]] if w else reg32_nums[args[0]]
            r_src = xmm_reg_nums[args[1]]
            self.code += prefix + rex(w, r_dst, 0, r_src) + b'\x0F\x2C' + mod_rm_reg(r_dst, r_src)
            return

        if name in mem_only_opcodes:
            assert len(args) == 1
            (w, opcode, sub_opcode) = mem_only_opcodes[name]
            self.code += rex_addr(w, 0, args[0]) + opcode + mod_rm_addr(sub_opcode, args[0])
            return

        if name == 'int':
            assert len(args) == 1
            if args[0] == '3':
                self.code += b'\xCC'
            else:
                self.code += b'\xCD' + struct.pack('<B', args[0])
            return
        if name == 'enter':
            assert len(args) == 2
            self.code += b'\xC8' + struct.pack('<HB', args[0], args[1])
            return
        if name == 'push':
            assert len(args) == 1
            if args[0] == 'fs':
                self.code += b'\x0F\xA0'
            elif args[0] == 'gs':
                self.code += b'\x0F\xA8'
            elif isinstance(args[0], int):
                if -128 <= args[0] <= 127:
                    self.code += b'\x6A' + struct.pack('<b', args[0])
                else:
                    self.code += b'\x68' + struct.pack('<i', args[0])
            else:
                reg = reg64_nums[args[0]]
                self.code += rex(0, 0, 0, reg) + bytes([0x50 | (reg & 7)])
            return
        if name == 'pop':
            assert len(args) == 1
            if args[0] == 'fs':
                self.code += b'\x0F\xA1'
            elif args[0] == 'gs':
                self.code += b'\x0F\xA9'
            else:
                reg = reg64_nums[args[0]]
                self.code += rex(0, 0, 0, reg) + bytes([0x58 | (reg & 7)])
            return

        if name in reg_only_opcodes:
            assert len(args) == 1
            (prefix, opcode, sub_opcode) = reg_only_opcodes[name]
            w = args[0] in reg64_nums
            reg = reg64_nums[args[0]] if w else reg32_nums[args[0]]
            self.code += prefix + rex(w, 0, 0, reg) + opcode + mod_rm_reg(sub_opcode, reg)
            return

        if name in {'movzx', 'movsx'}:
            assert len(args) == 2
            w = args[0] in reg64_nums
            force = 0
            if w:
                r_dst = reg64_nums[args[0]]
                if args[1] in reg8_nums:
                    r_src = reg8_nums[args[1]]
                    opcode = b'\x0F\xB6' if name == 'movzx' else b'\x0F\xBE'
                elif args[1] in reg16_nums:
                    r_src = reg16_nums[args[1]]
                    opcode = b'\x0F\xB7' if name == 'movzx' else b'\x0F\xBF'
                else:
                    r_src = reg32_nums[args[1]]
                    assert name == 'movsx'
                    opcode = b'\x63'
            else:
                r_dst = reg32_nums[args[0]]
                if args[1] in reg8_hi_nums:
                    r_src = reg8_hi_nums[args[1]]
                    assert r_dst < 8 # high parts are only usable without rex
                    opcode = b'\x0F\xB6' if name == 'movzx' else b'\x0F\xBE'
                elif args[1] in reg8_nums:
                    r_src = reg8_nums[args[1]]
                    force = r_src >= 4 # force REX when using "new" low regs
                    opcode = b'\x0F\xB6' if name == 'movzx' else b'\x0F\xBE'
                else:
                    r_src = reg16_nums[args[1]]
                    opcode = b'\x0F\xB7' if name == 'movzx' else b'\x0F\xBF'
            self.code += rex(w, r_dst, 0, r_src, force) + opcode + mod_rm_reg(r_dst, r_src)
            return
        if name == 'bswap':
            assert len(args) == 1
            w = args[0] in reg64_nums
            reg = reg64_nums[args[0]] if w else reg32_nums[args[0]]
            self.code += rex(w, 0, 0, reg) + b'\x0F' + bytes([0xC8 | (reg & 7)])
            return

        if name in bmi_vex_ndd_opcodes:
            assert len(args) == 2
            (p, m, opcode, sub_opcode) = bmi_vex_ndd_opcodes[name]
            w = args[0] in reg64_nums
            r_dst = reg64_nums[args[0]] if w else reg32_nums[args[0]]
            if isinstance(args[1], Address): # load-op
                self.code += vex(w, r_dst, args[1].index, args[1].base, p, m, 0, r_dst) + opcode + mod_rm_addr(sub_opcode, args[1])
            else:
                r_src = reg64_nums[args[1]] if w else reg32_nums[args[1]]
                self.code += vex(w, r_dst, 0, r_src, p, m, 0, r_dst) + opcode + mod_rm_reg(sub_opcode, r_src)
            return
        if name in bmi_vex_opcodes:
            assert len(args) == 3
            (p, m, opcode) = bmi_vex_opcodes[name]
            if name in {'bextr', 'bzhi', 'sarx', 'shlx', 'shrx'}:
                args = [args[0], args[2], args[1]] # funny arg order
            w = args[0] in reg64_nums
            r_dst = reg64_nums[args[0]] if w else reg32_nums[args[0]]
            r_src0 = reg64_nums[args[1]] if w else reg32_nums[args[1]]
            if isinstance(args[2], Address): # load-op
                self.code += vex(w, r_dst, args[2].index, args[2].base, p, m, 0, r_src0) + opcode + mod_rm_addr(r_dst, args[2])
            else:
                r_src1 = reg64_nums[args[2]] if w else reg32_nums[args[2]]
                self.code += vex(w, r_dst, 0, r_src1, p, m, 0, r_src0) + opcode + mod_rm_reg(r_dst, r_src1)
            return

        if name in avx_opcodes:
            (w, p, m, opcode, template) = avx_opcodes[name]
            if template == 0:
                if len(args) == 2:
                    args = [args[0], args[0], args[1]]
                assert len(args) == 3
                l = args[0] in ymm_reg_nums
                r_dst = ymm_reg_nums[args[0]] if l else xmm_reg_nums[args[0]]
                r_src0 = ymm_reg_nums[args[1]] if l else xmm_reg_nums[args[1]]
                if isinstance(args[2], Address): # load-op
                    self.code += vex(w, r_dst, args[2].index, args[2].base, p, m, l, r_src0) + opcode + mod_rm_addr(r_dst, args[2])
                else:
                    r_src1 = ymm_reg_nums[args[2]] if l else xmm_reg_nums[args[2]]
                    self.code += vex(w, r_dst, 0, r_src1, p, m, l, r_src0) + opcode + mod_rm_reg(r_dst, r_src1)
                return
            if template == 1:
                assert len(args) == 2
                l = args[0] in ymm_reg_nums
                r_dst = ymm_reg_nums[args[0]] if l else xmm_reg_nums[args[0]]
                if isinstance(args[1], Address): # load-op
                    self.code += vex(w, r_dst, args[1].index, args[1].base, p, m, l) + opcode + mod_rm_addr(r_dst, args[1])
                elif isinstance(args[1], RelLabel):
                    self.code += vex(w, r_dst, 0, 0, p, m, l) + opcode
                    disp = args[1].code_offset - (len(self.code) + 5)
                    self.code += mod_rm_addr(r_dst, Address('rip', 0, 0, disp))
                else:
                    r_src = ymm_reg_nums[args[1]] if l else xmm_reg_nums[args[1]]
                    self.code += vex(w, r_dst, 0, r_src, p, m, l) + opcode + mod_rm_reg(r_dst, r_src)
                return
            if template == 2:
                if len(args) == 3:
                    args = [args[0], args[0], args[1], args[2]]
                assert len(args) == 4
                l = args[0] in ymm_reg_nums
                r_dst = ymm_reg_nums[args[0]] if l else xmm_reg_nums[args[0]]
                r_src0 = ymm_reg_nums[args[1]] if l else xmm_reg_nums[args[1]]
                if isinstance(args[2], Address): # load-op
                    self.code += vex(w, r_dst, args[2].index, args[2].base, p, m, l, r_src0) + opcode + mod_rm_addr(r_dst, args[2])
                else:
                    r_src1 = ymm_reg_nums[args[2]] if l else xmm_reg_nums[args[2]]
                    self.code += vex(w, r_dst, 0, r_src1, p, m, l, r_src0) + opcode + mod_rm_reg(r_dst, r_src1)
                self.code += bytes([args[3]])
                return
            if template == 3:
                assert len(args) == 3
                l = args[0] in ymm_reg_nums
                r_dst = ymm_reg_nums[args[0]] if l else xmm_reg_nums[args[0]]
                if isinstance(args[1], Address): # load-op
                    self.code += vex(w, r_dst, args[1].index, args[1].base, p, m, l) + opcode + mod_rm_addr(r_dst, args[1])
                else:
                    r_src1 = ymm_reg_nums[args[1]] if l else xmm_reg_nums[args[1]]
                    self.code += vex(w, r_dst, 0, r_src1, p, m, l) + opcode + mod_rm_reg(r_dst, r_src1)
                self.code += bytes([args[2]])
                return
            if name == 'vinsertf128':
                l = 1
                assert len(args) == 4
                r_dst = ymm_reg_nums[args[0]]
                r_src0 = ymm_reg_nums[args[1]]
                r_src1 = xmm_reg_nums[args[2]]
                self.code += vex(w, r_dst, 0, r_src1, p, m, l, r_src0) + opcode + mod_rm_reg(r_dst, r_src1) + bytes([args[3]])
                return
            if name == 'vmaskmovps':
                assert len(args) == 3
                l = args[1] in ymm_reg_nums
                r_src0 = ymm_reg_nums[args[1]] if l else xmm_reg_nums[args[1]]
                r_src1 = ymm_reg_nums[args[2]] if l else xmm_reg_nums[args[2]]
                self.code += vex(w, r_src1, args[0].index, args[0].base, p, m, l, r_src0) + opcode + mod_rm_addr(r_src1, args[0])
                return
            if name in {'vblendvpd', 'vblendvps', 'vpblendvb'}:
                assert len(args) == 4
                l = args[1] in ymm_reg_nums
                r_dst = ymm_reg_nums[args[0]] if l else xmm_reg_nums[args[0]]
                r_src0 = ymm_reg_nums[args[1]] if l else xmm_reg_nums[args[1]]
                r_src1 = ymm_reg_nums[args[2]] if l else xmm_reg_nums[args[2]]
                r_src2 = ymm_reg_nums[args[3]] if l else xmm_reg_nums[args[3]]
                self.code += vex(w, r_dst, 0, r_src1, p, m, l, r_src0) + opcode + mod_rm_reg(r_dst, r_src1) + bytes([r_src2 << 4])
                return
            raise RuntimeError("don't know how to parse line %s" % tokens)

        if name == 'dd':
            for arg in args:
                self.code += struct.pack('<I', arg)
        elif name == 'dq':
            for arg in args:
                self.code += struct.pack('<Q', arg)
        else:
            raise RuntimeError("don't know how to parse line %s" % tokens)

def asm(filename, windows):
    parser = Parser()
    if_stack = [True]
    with open(filename) as f:
        for line in f:
            if ';' in line:
                line = line[:line.index(';')] # remove comments
            line = line.strip()
            if not line:
                continue # skip blank lines

            if parser.cur_macro_args is not None:
                if line == '%endmacro':
                    parser.macros[parser.cur_macro_args[0]] = (parser.cur_macro, int(parser.cur_macro_args[1]))
                    parser.cur_macro_args = None
                    del parser.cur_macro
                else:
                    parser.cur_macro.append(line)
                continue
            if line.startswith('%macro '):
                line = line.split()
                assert len(line) == 3
                parser.cur_macro_args = line[1:]
                parser.cur_macro = []
                continue
            if line == '%ifdef _WIN32':
                if_stack.append(windows)
                continue
            if line == '%ifndef _WIN32':
                if_stack.append(not windows)
                continue
            if line == '%else':
                if if_stack[-2] == True:
                    if_stack[-1] = not if_stack[-1]
                continue
            if line == '%endif':
                if_stack.pop()
                continue

            if if_stack[-1]:
                if line.startswith('%define '):
                    line = line.split()
                    assert len(line) == 3
                    parser.defines[line[1]] = line[2]
                    continue

                parser.line_to_code(line)

    if windows:
        return make_obj(filename, parser.labels, parser.globals, parser.code)
    else:
        return make_elf(filename, parser.labels, parser.globals, parser.code)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--windows', action='store_true')
    parser.add_argument('input_filename')
    parser.add_argument('output_filename')
    args = parser.parse_args()

    out = asm(args.input_filename, args.windows)
    with open(args.output_filename, 'wb') as f:
        f.write(out)

if __name__ == '__main__':
    main()
