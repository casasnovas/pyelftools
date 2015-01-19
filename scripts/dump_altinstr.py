#!/usr/bin/env python

from __future__ import print_function
import sys
import os
from termcolor import colored

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, 'python'))

from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

def print_pass_failure(msg, cond):
    sys.stdout.write('{:<60}'.format(msg))
    print(colored('[KO]', 'red')) if cond  else print(colored('[OK]', 'green'))

def get_section(e, section_name):
    section = e.get_section_by_name(section_name)
    print_pass_failure('\tLooking for section %s' % section_name,
                       section is None)
    return section

def get_symbol(e, sym_name):
    symtab = get_section(e, '.symtab')
    sym = symtab.get_symbol_by_name(sym_name)
    print_pass_failure('\tLooking symbol for symbol [%s]' % sym_name,
                       sym is None)
    return sym

def get_symbol_for_section(e, section):
    symtab = get_section(e, '.symtab')
    for sym in symtab.iter_symbols():
        if sym['st_shndx'] == section.index:
            break
    print_pass_failure('\tLooking symbol for section %s[%d]' % (section.name, section.index),
                       sym is None)
    return sym

def get_relocs_to_sym(reloc_section, symbol):
    return [ r for r in reloc_section.iter_relocations() if r['r_info_sym'] == symbol.index ]

def get_addresses_from_altinstr(alt_relocs_section, alt_repl_relocs):
    addresses = []
    prev = None
    addends = [r['r_addend'] for r in alt_repl_relocs]
    for reloc in alt_relocs_section.iter_relocations():
        if reloc['r_addend'] in addends:
            addresses.append(prev)
        prev = reloc
    return addresses

def get_func_name(dwarf, address):
    for CU in dwarf.iter_CUs():
        for DIE in CU.iter_DIEs():
            try:
                if DIE.tag == 'DW_TAG_subprogram':
                    lowpc = DIE.attributes['DW_AT_low_pc'].value
                    highpc = DIE.attributes['DW_AT_high_pc'].value
                    if lowpc <= address <= highpc:
                        return DIE.attributes['DW_AT_name'].value
            except KeyError:
                continue
    print('Function name not found for address %s' % hex(address))
    return None

def decode_file_line(dwarfinfo, address):
    # Go over all the line programs in the DWARF information, looking for
    # one that describes the given address.
    for CU in dwarfinfo.iter_CUs():
        # First, look at line programs to find the file/line for the address
        lineprog = dwarfinfo.line_program_for_CU(CU)
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None or entry.state.end_sequence:
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate and prevstate.address <= address < entry.state.address:
                filename = lineprog['file_entry'][prevstate.file - 1].name
                line = prevstate.line
                return filename, line
            prevstate = entry.state
    return None, None

def dump_wrong_fixups(dwarf, relocs):
    print('\tFound problematics __ex_table fixup with:')
    tuples = []
    for reloc in relocs:
        filename, line = decode_file_line(dwarf, reloc['r_addend'])
        func_name = get_func_name(dwarf, reloc['r_addend'])
        if [filename, line] not in tuples:
            print('\t\t%s:%d from %s()' % (filename, line, func_name))
            tuples.append([filename, line])

def print_reloc(reloc):
    print('reloc:')
    print('\t r_offset:' + hex(reloc['r_offset']))
    print('\t r_addend:' + hex(reloc['r_addend']))


def main(filename):
    print('Dumping:', filename)

    with open(filename, 'rb') as f:
        elf = ELFFile(f)

        if not elf.has_dwarf_info():
            print(colored('\tFile has no DWARF info.', 'red'))
        else:
            dwarf = elf.get_dwarf_info()

        ex_table                       = get_section(elf, '__ex_table')
        ex_table.relocs_section        = get_section(elf, '.rela__ex_table')
        altinstructions                = get_section(elf, '.altinstructions')
        altinstructions.relocs_section = get_section(elf, '.rela.altinstructions')
        altinstr_repl                  = get_section(elf, '.altinstr_replacement')
        altinstr_repl.symbol           = get_symbol_for_section(elf, altinstr_repl)
        relocs_in_alt_repl             = get_relocs_to_sym(ex_table.relocs_section,
                                                           altinstr_repl.symbol)

        matching_text_relocs  = get_addresses_from_altinstr(altinstructions.relocs_section,
                                                               relocs_in_alt_repl)

        if len(matching_text_relocs):
            dump_wrong_fixups(dwarf, matching_text_relocs)

if __name__ == '__main__':
    for filename in sys.argv[1:]:
        main(filename)
