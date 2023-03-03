import sys
import cocotb

from cocotb.decorators import coroutine
from cocotb.triggers import RisingEdge

from adapters.tilelink.adapter import tlAdapter
from adapters.tilelink.definitions import *

INT_MEIP = 0x4
INT_SEIP = 0x8
INT_MTIP = 0x1
INT_MSIP = 0x2

class intPorts():
    __slots__ = ('a_seip', 'a_meip', 'a_msip', 'a_mtip', 'b_seip', 'b_meip', 'b_msip', 'b_mtip')

    def __init__(self):
        for attr in self.__slots__:
            setattr(self, attr, None)

class tileAdapter(): #adapt to new instrumented dut structure with two tiles
    def __init__(self, dut, port_names, monitor, debug=False):
        self.dut = dut
        self.debug = debug
        self.drive = False


        #sort ports by "a_"/"b_" beforehand
        port_names_a = []
        port_names_b = []
        other = []

        for name in port_names:
            if name[:2] == 'a_':
                port_names_a.append(name)
            elif name[:2] == 'b_':
                port_names_b.append(name)
            else:
                other.append(name)

        tl_port_names_a, int_port_names_a, reset_vector_port_a, others_a = self.sort_ports(port_names_a)

        tl_port_names_b, int_port_names_b, reset_vector_port_b, others_b = self.sort_ports(port_names_b)

        pc_names = monitor[0]
        valid_names = monitor[1]

        for name in tl_port_names_a:
            if '_b_' in name:
                protocol = TL_C

        #create two adapters for each copy of the instrumented dut
        self.tl_adapter_a = tlAdapter(dut, tl_port_names_a, protocol, 64, debug)
        self.tl_adapter_b = tlAdapter(dut, tl_port_names_b, protocol, 64, debug)

        self.int_ports = intPorts()
        self.set_int_ports('a_', int_port_names_a)
        self.set_int_ports('b_', int_port_names_b)

        self.reset_vector_port_a = getattr(self.dut, reset_vector_port_a)
        self.reset_vector_port_b = getattr(self.dut, reset_vector_port_b)

        self.reset_vector = 0x10000
        self.reset_vector_port_a.value = self.reset_vector
        self.reset_vector_port_b.value = self.reset_vector

        self.monitor_pc_a = getattr(self.dut, pc_names[0])
        self.monitor_valid_a = getattr(self.dut, valid_names[0])

        self.monitor_pc_b = getattr(self.dut, pc_names[1])
        self.monitor_valid_b = getattr(self.dut, valid_names[1])

        self.intr = 0

    def set_int_ports(self, prefix, int_port_names):
        for name in int_port_names:
            if 'in_2_sync_0' in name: setattr(self.int_ports, prefix + 'seip', getattr(self.dut, name))
            if 'in_1_sync_0' in name: setattr(self.int_ports, prefix + 'meip', getattr(self.dut, name))
            if 'in_0_sync_0' in name: setattr(self.int_ports, prefix + 'msip', getattr(self.dut, name))
            if 'in_0_sync_1' in name: setattr(self.int_ports, prefix + 'mtip', getattr(self.dut, name))


    def sort_ports(self, port_names):
        tl_port_names = []
        int_port_names = []
        others = []
        for name in port_names:
            if '_tl_' in name:
                tl_port_names.append(name)
            elif '_int' in name:
                int_port_names.append(name)
            elif 'reset_vector' in name:
                reset_vector_port = name
            else:
                others.append(name)

        return tl_port_names, int_port_names, reset_vector_port, others


    def debug_print(self, message):
        if self.debug:
            print(message)

    def assert_intr(self, intr):
        if intr == self.intr:
            return

        self.intr = intr
        meip = int((intr & INT_MEIP) == INT_MEIP)
        seip = int((intr & INT_SEIP) == INT_SEIP)
        mtip = int((intr & INT_MTIP) == INT_MTIP)
        msip = int((intr & INT_MSIP) == INT_MSIP)

        self.int_ports.a_seip.value = seip
        self.int_ports.a_meip.value = meip
        self.int_ports.a_msip.value = msip
        self.int_ports.a_mtip.value = mtip

        self.int_ports.b_seip.value = seip
        self.int_ports.b_meip.value = meip
        self.int_ports.b_msip.value = msip
        self.int_ports.b_mtip.value = mtip

    def pc_valid(self):
        return self.monitor_valid_a.value & self.monitor_valid_b.value

    @coroutine
    def interrupt_handler(self, ints): #TODO adapt interrupt to both copies
        if not ints:
            return

        while self.drive:
            if self.pc_valid():
                pc = self.monitor_pc.value & ((1 << len(self.monitor_pc.value)) - 1)
                if pc in ints.keys():
                    self.debug_print('[RTLHost] interrupt_handler, pc: {:016x}, INT: {:01x}'.
                                     format(pc, ints[pc]))
                    self.assert_intr(ints[pc])
            yield RisingEdge(self.dut.clock)


    def probe_tohost(self, tohost_addr):  #TODO check what this does and adapt
        self.tl_adapter_a.probe_block(tohost_addr)
        self.tl_adapter_b.probe_block(tohost_addr)

    def check_assert(self):  #TODO check what this does and adapt
        return self.dut.metaAssert.value

    def start(self, memory_a, memory_b, ints): #two memory sections, containing both instructions and data
        if memory_a.__class__.__name__ != 'dict' or memory_b.__class__.__name__ != 'dict':
            raise Exception('RocketTile Adapter must receive address map to drive DUT')

        self.drive = True
        self.tl_adapter_a.start(memory_a)
        self.tl_adapter_b.start(memory_b)
        self.intr_handler = cocotb.fork(self.interrupt_handler(ints))

    @coroutine
    def stop(self):
        self.drive = False
        while self.tl_adapter_a.onGoing() & self.tl_adapter_b.onGoing():
            yield RisingEdge(self.dut.clock)
        self.tl_adapter_a.stop()
        self.tl_adapter_b.stop()
        while self.tl_adapter_a.isRunning() & self.tl_adapter_b.isRunning():
            yield RisingEdge(self.dut.clock)

        self.int_ports.a_seip.value = 0
        self.int_ports.a_meip.value = 0
        self.int_ports.a_msip.value = 0
        self.int_ports.a_mtip.value = 0

        self.int_ports.b_seip.value = 0
        self.int_ports.b_meip.value = 0
        self.int_ports.b_msip.value = 0
        self.int_ports.b_mtip.value = 0

        self.intr = 0
