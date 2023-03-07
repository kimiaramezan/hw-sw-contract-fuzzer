import os
import subprocess
import shutil
import random

from HSCSim.host import hscInput
from RTLSim.host import rtlInput
from mutator import simInput, templates, P_M, P_S, P_U, V_U

class rvPreProcessor():
    def __init__(self, cc, elf2hex, template='Template', out_base ='.', proc_num=0):
        self.cc = cc
        self.elf2hex = elf2hex
        self.template = template
        self.base = out_base
        self.proc_num = proc_num

        self.er_num = 0
        self.cc_args = [ cc, '-march=rv64g', '-mabi=lp64', '-static', '-mcmodel=medany',
                         '-fvisibility=hidden', '-nostdlib', '-nostartfiles',
                         '-I', '{}/include'.format(template),
                         '-T', '{}/include/link.ld'.format(template) ]

        self.elf2hex_args = [ elf2hex, '--bit-width', '64', '--input' ]

    def get_symbols(self, elf_name, sym_name):
        # symbol_file = self.base + '/.input.symbols'
        fd = open(sym_name, 'w')
        subprocess.call([ 'nm', elf_name], stdout=fd )
        fd.close()

        symbols = {}
        fd = open(sym_name, 'r')
        lines = fd.readlines()
        fd.close()

        for line in lines:
            symbol = line.split(' ')[2]
            addr = line.split(' ')[0]
            symbols[symbol[:-1]] = int(addr, 16)

        return symbols

    def write_isa_intr(self, isa_input, rtl_input, epc):
        fd = open(rtl_input.intrfile, 'r')
        tuples = [ line.split(':') for line in fd.readlines() ]
        fd.close()

        # TODO, assert interrupt multiple time
        assert len(tuples) == 1, 'Interrupt must be asserted only one time'
        val = int(tuples[0][1], 2)

        fd = open(isa_input.intrfile, 'w')
        fd.write('{:016x}:{:04b}\n'.format(epc, val))
        fd.close()

    def generate_assembly(self, template_lines, sim_input, data, num_data_sections, section_size):
        prefix_insts = sim_input.get_prefix()
        insts = sim_input.get_insts()
        suffix_insts = sim_input.get_suffix()

        assembly = []
        for line in template_lines:
            assembly.append(line)
            if '_fuzz_prefix:' in line:
                for inst in prefix_insts:
                    assembly.append(inst + ';\n')

            if '_fuzz_main:' in line:
                for inst in insts:
                    assembly.append(inst + ';\n')

            if '_fuzz_suffix:' in line:
                for inst in suffix_insts:
                    assembly.append(inst + ';\n')

            for n in range(num_data_sections):
                start = n * section_size
                end = start + section_size
                if '_random_data{}'.format(n) in line:
                    k = 0
                    for i in range(start, end, 2):
                        label = ''
                        if i > start + 2 and i < end - 4:
                            label = 'd_{}_{}:'.format(n, k)
                            k += 1

                        assembly.append('{:<16}.dword 0x{:016x}, 0x{:016x}\n'.\
                                        format(label, data[i], data[i+1]))
        return assembly

    def compile_asm(self, extra_args, asm_name, elf_name):
        cc_args = self.cc_args + extra_args + [ asm_name, '-o', elf_name ]

        cc_ret = -1
        while True:
            cc_ret = subprocess.call(cc_args)
            # if cc_ret == -9: cc process is killed by OS due to memory usage
            if cc_ret != -9: break
        return cc_ret

    def process(self, sim_input: simInput, data_a: list, data_b: list, intr: bool, num_data_sections=6): #TODO check this section, especially for data
        section_size = len(data_a) // num_data_sections

        assert len(data_a) == len(data_b), 'data sections have to be of equal length'
        assert data_a, 'Empty data can not be processed'
        assert (section_size & (section_size - 1)) == 0, \
            'Number of memory blocks should be power of 2'

        version = sim_input.get_template()
        test_template = self.template + '/rv64-{}.S'.format(templates[version])

        if intr: DINTR = ['-DINTERRUPT']
        else: DINTR = []
        extra_args = DINTR + [ '-I', '{}/include/p'.format(self.template) ]
        if version in [ V_U ]:
            rand = data_a[0] & 0xffffffff
            extra_args = DINTR + [ '-DENTROPY=0x{:08x}'.format(rand), '-std=gnu99', '-O2',
                                   '-I', '{}/include/v'.format(self.template),
                                   '{}/include/v/string.c'.format(self.template),
                                   '{}/include/v/vm.c'.format(self.template) ]

        si_name = self.base + '/.input_{}.si'.format(self.proc_num)
        asm_name_a = self.base + '/.input_{}_a.S'.format(self.proc_num)
        asm_name_b = self.base + '/.input_{}_b.S'.format(self.proc_num)
        elf_name_a = self.base + '/.input_{}_a.elf'.format(self.proc_num)
        elf_name_b = self.base + '/.input_{}_b.elf'.format(self.proc_num)
        hex_name = self.base + '/.input_{}.hex'.format(self.proc_num)
        sym_name = self.base + '/.input_{}.symbols'.format(self.proc_num)
        rtl_intr_name = self.base + '/.input_{}.rtl.intr'.format(self.proc_num)
        isa_intr_name = self.base + '/.input_{}.isa.intr'.format(self.proc_num)

        sim_input_ints = sim_input.ints.copy()
        insts = sim_input.get_insts()

        ints = []
        for inst in insts[:-1]:
            INT = sim_input_ints.pop(0)
            if 'la' in inst:
                ints.append(INT)
                ints.append(0)
            else:
                ints.append(INT)

        sim_input.save(si_name, (data_a, data_b))

        fd = open(test_template, 'r')
        template_lines = fd.readlines()
        fd.close()

        assembly_a = self.generate_assembly(template_lines, sim_input, data_a, num_data_sections, section_size)

        assembly_b = self.generate_assembly(template_lines, sim_input, data_b, num_data_sections, section_size)

        fd = open(asm_name_a, 'w')
        fd.writelines(assembly_a)
        fd.close()
        fd = open(asm_name_b, 'w')
        fd.writelines(assembly_b)
        fd.close()

        cc_ret_a = self.compile_asm(extra_args, asm_name_a, elf_name_a)
        cc_ret_b = self.compile_asm(extra_args, asm_name_b, elf_name_b)
        
        if cc_ret_a == 0 and cc_ret_b == 0:

            elf2hex_args = self.elf2hex_args + [ elf_name_a, '--output', hex_name]
            subprocess.call(elf2hex_args)
            symbols= self.get_symbols(elf_name_a, sym_name)

            if intr:
                fuzz_main = symbols['_fuzz_main']
                fd = open(rtl_intr_name, 'w')
                for i, INT in enumerate(ints):
                    if INT:
                        fd.write('{:016x}:{:04b}\n'.format(fuzz_main + 4 * i, INT))
                fd.close()

            max_cycles = 6000
            if version in [ V_U ]:
                max_cycles = 200000

            hsc_input = hscInput(elf_name_a, elf_name_b, isa_intr_name)
            rtl_input = rtlInput(hex_name, rtl_intr_name, data_a, data_b, symbols, max_cycles)
        else:
            hsc_input = None
            rtl_input = None
            symbols = None

        return (hsc_input, rtl_input, symbols)
