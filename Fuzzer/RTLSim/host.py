import sys
import cocotb

from cocotb.decorators import coroutine
from cocotb.triggers import Timer, RisingEdge
from bitarray import bitarray
from hashlib import shake_128
from itertools import repeat
from reader.tile_reader import tileSrcReader
from adapters.tile_adapter import tileAdapter

NO_LEAK = 0
LEAK = 1
TIME_OUT = 2 #TODO do we need this? Theoretically programs should terminate if sail behaviour == rtl behaviour, could block 'longer' programs from being tested
#ILL_MEM = -1

DRAM_BASE = 0x80000000

ROCKET_COV_LEN = 1730
BOOM_COV_LEN = 18808

class rtlInput(): #GG now with two data sections
    def __init__(self, hexfile, intrfile, data_a, data_b, symbols, max_cycles):
        self.hexfile = hexfile
        self.intrfile = intrfile
        self.data_a = data_a
        self.data_b = data_b
        self.symbols = symbols
        self.max_cycles = max_cycles

class rvRTLhost():
    def __init__(self, dut, toplevel, rtl_sig_file, debug=False):
        source_info = 'infos/' + toplevel + '_info.txt'
        reader = tileSrcReader(source_info)

        paths = reader.return_map()

        #TODO add more info categories: coverage output, observable signals (attacker model!), ...

        port_names = paths['port_names'] 
        monitor_pc = paths['monitor_pc']
        monitor_valid = paths['monitor_valid']
        monitor = (monitor_pc, monitor_valid)

        self.pc_a = getattr(dut, monitor_pc[0])
        self.pc_valid_a = getattr(dut, monitor_valid[0])

        self.pc_b = getattr(dut, monitor_pc[1])
        self.pc_valid_b = getattr(dut, monitor_valid[1])

        self.rtl_sig_file = rtl_sig_file
        self.debug = debug

        self.cov_output = getattr(dut, "cov_" + toplevel)

        self.dut = dut
        self.adapter = tileAdapter(dut, port_names, monitor, self.debug)

        self.coverage_map = bitarray(repeat(0,2 ** 24)) #UP
        self.last_idx = 0
        self.coverage_bits = -1

        if toplevel == "RocketTile":
            self.cov_reset_val = int('1' * ROCKET_COV_LEN, 2)
        else:
            self.cov_reset_val = int('1' * BOOM_COV_LEN, 2)

    def debug_print(self, message):
        if self.debug:
            print(message)

    def set_bootrom(self):
        bootrom_addrs = []
        memory = {}
        bootrom = [ 0x00000297, # auipc t0, 0x0
                    0x02028593, # addi a1, t0, 32
                    0xf1402573, # csrr a0, mhartid
                    0x0182b283, # ld t0, 24(t0)
                    0x00028067, # jr t0
                    0x00000000, # no data
                    0x80000000, # Jump address
                    0x00000000,
                    0x00000000,
                    0x00000000,
                    0x00000000,
                    0x00000000,
                    0x00000000,
                    0x00000000,
                    0x00000000,
                    0x00000000 ] # no data

        for i in range(0, len(bootrom), 2):
            bootrom_addrs.append(0x10000 + i * 4)
            memory[0x10000 + i * 4] = (bootrom[i+1] << 32) | bootrom[i]

        return (bootrom_addrs, memory)

    @coroutine
    def clock_gen(self, clock, period=2):
        while True:
            clock.value = 1
            yield Timer(period / 2)
            clock.value = 0
            yield Timer(period / 2)

    @coroutine
    def reset(self, clock, metaReset, reset, timer=5):
        clkedge = RisingEdge(clock)

        metaReset.value = 1
        for i in range(timer):
            yield clkedge
        metaReset.value = 0

        assert self.cov_output.value == self.cov_reset_val, '[meta] coverage not reset {}'.format(self.cov_output.value)

        reset.value = 1
        for i in range(timer):
            yield clkedge
        reset.value = 0
    
    def cov_gen(self):
        idx = int.from_bytes(shake_128(self.cov_output.value.buff).digest(3), byteorder='big')
        # comment in to debug coverage
        #self.debug_print('idx: {}'.format(idx ^ self.last_idx))
        self.coverage_map[idx ^ self.last_idx] = 1
        self.last_idx = idx >> 1

        if self.coverage_bits != -1:
            self.coverage_bits = self.coverage_bits & self.cov_output.value
            #self.debug_print("cov_bits:{},{}".format(self.coverage_bits, type(self.coverage_bits)))
        else:
            self.coverage_bits = self.cov_output.value

    def check_pc_eq(self): # check pc for equal validity and values (if valid)
        if self.pc_valid_a.value != self.pc_valid_b.value:
            self.debug_print('[RTLHost] PC validity difference a: {} b: {}'.format(self.pc_valid_a.value, self.pc_valid_b.value))
            self.debug_print('[RTLHost] PC values a: {} b: {}'.format(hex(int(self.pc_a.value)), hex(int(self.pc_b.value))))
            return False
        elif self.pc_valid_a.value and self.pc_a.value != self.pc_b.value:
            self.debug_print('[RTLHost] PC value difference a: {} b: {}'.format(hex(int(self.pc_a.value)), hex(int(self.pc_b.value))))
            return False
        return True

    def save_signature(self, memory, sig_start, sig_end, data_addrs, sig_file):
        fd = open(sig_file, 'w')
        for i in range(sig_start, sig_end, 16):
            dump = '{:016x}{:016x}\n'.format(memory[i+8], memory[i])
            fd.write(dump)

        for (data_start, data_end) in data_addrs:
            for i in range(data_start, data_end, 16):
                dump = '{:016x}{:016x}\n'.format(memory[i+8], memory[i])
                fd.write(dump)

        fd.close()

    def get_covsum(self):
        #cov_mask = (1 << len(self.cov_output)) - 1
        #print("ATTENTION {}".format(self.cov_output.value))
        return (self.coverage_bits, self.coverage_map)

    @coroutine
    def run_test(self, rtl_input: rtlInput, assert_intr: bool):

        self.debug_print('[RTLHost] Start RTL simulation')

        self.coverage_map = bitarray(repeat(0,2 ** 24)) # UP
        self.last_idx = 0
        self.coverage_bits = -1

        fd = open(rtl_input.hexfile, 'r')
        lines = fd.readlines()
        fd.close()

        max_cycles = rtl_input.max_cycles

        symbols = rtl_input.symbols
        _start = symbols['_start']
        _end = symbols['_end_main']

        (bootrom_addrs, memory) = self.set_bootrom()
        for (i, addr) in enumerate(range(_start, _end + 36, 8)):
            memory[addr] = int(lines[i], 16)

        tohost_addr = symbols['tohost']
        sig_start = symbols['begin_signature']
        sig_end = symbols['end_signature']

        memory[tohost_addr] = 0
        for addr in range(sig_start // 8 * 8, sig_end, 8):
            memory[addr] = 0

        memory_a = memory
        memory_b = memory.copy()

        data_a = rtl_input.data_a #GG now handling two different data sections
        data_b = rtl_input.data_b
        data_addrs = []
        offset = 0
        for n in range(6): 
            data_start = symbols['_random_data{}'.format(n)]
            data_end = symbols['_end_data{}'.format(n)]
            data_addrs.append((data_start, data_end))

            for i, addr in enumerate(range(data_start // 8 * 8, data_end // 8 * 8, 8)):
                word = data_a[i + offset]
                memory_a[addr] = word
                word = data_b[i + offset]
                memory_b[addr] = word

            offset += (data_end - data_start) // 8

        ints = {}
        if assert_intr:
            fd = open(rtl_input.intrfile, 'r')
            intr_pairs = [ line.split(':') for line in fd.readlines() ]
            fd.close()

            for pair in intr_pairs:
                ints[int(pair[0], 16)] = int(pair[1], 2)

        clk = self.dut.clock
        clk_driver = cocotb.fork(self.clock_gen(clk))
        clkedge = RisingEdge(clk)

        yield self.reset(clk, self.dut.metaReset, self.dut.reset)

        assert self.cov_output.value == self.cov_reset_val, 'coverage not reset {}'.format(self.cov_output.value)

        leak = False

        self.adapter.start(memory_a, memory_b, ints)
        for i in range(max_cycles):
            yield clkedge
            self.cov_gen()
            pc_equal = self.check_pc_eq()
            leak = leak or not pc_equal
            if i % 100 == 0:
                tohost_a = memory_a[tohost_addr]
                tohost_b = memory_b[tohost_addr] 
                if tohost_a: # or tohost_b: # one core terminated TODO either wait for other to finish, maybe get and ouput pc from other one
                    self.debug_print('a done')
                    break
                elif tohost_b:
                    self.debug_print('b done')
                    break
                else:
                    self.adapter.probe_tohost(tohost_addr)

        yield self.adapter.stop()
        clk_driver.kill()
        self.debug_print('[RTLHost] End of RTL simulation')

        self.debug_print('[RTLHost] PC leak: {}'.format(leak))

        if (tohost_a and not tohost_b) or (not tohost_a and tohost_b): #one finished earlier
            self.debug_print('[RTLHost] HTIF observed timing leak')
            return_val = LEAK

        elif tohost_a and tohost_b: #both finished in the same 100 cycle batch
            self.debug_print('[RTLHost] HTIF observations equal')
            if leak:
                return_val = LEAK
            else:
                return_val = NO_LEAK
        
        else: # none finished in time timed out (this should only happen if a program take unforseen many cycles per instruction)
            self.debug_print('[RTLHost] Timeout, max_cycle={}'.format(max_cycles))
            return_val = TIME_OUT

        
        return (return_val, self.get_covsum())
        
        # GG TODO maybe make new checks for memory as in "same parts were accessed", however, this depends on observable stuff
        # Check all the CPU's memory access operations occurs in DRAM
        # mem_check = True
        # for addr in memory_a.keys():
        #     if addr not in bootrom_addrs and addr < DRAM_BASE:
        #         mem_check = False
        # for addr in memory_b.keys():
        #     if addr not in bootrom_addrs and addr < DRAM_BASE:
        #         mem_check = False

        # if not mem_check:
        #     return (ILL_MEM, self.get_covsum())


        #if self.adapter.check_assert():
        #    self.debug_print('[RTLHost] Assertion Failure')
        #    return (ASSERTION_FAIL, self.get_covsum())

        #self.save_signature(memory, sig_start, sig_end, data_addrs, self.rtl_sig_file)
