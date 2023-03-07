import os
import shutil
from typing import Tuple
import psutil
import signal
from threading import Timer

from HSCSim.host import rvHSChost
from ISASim.host import rvISAhost
from RTLSim.host import rvRTLhost

from src.preprocessor import rvPreProcessor
from src.signature_checker import sigChecker
from src.mutator import simInput, rvMutator
from src.multicore_manager import proc_state, procManager

ISA_TIME_LIMIT = 1

def save_err(out: str, proc_num: int, manager: procManager, stop_code: int):

    if stop_code == proc_state.NORMAL:
        return

    status = proc_state.tpe[stop_code]

    manager.P('state')
    fd = open(out + '/fuzz_log', 'a')
    fd.write('[DifuzzRTL] Thread {}: {} occurred\n'.format(proc_num, status))
    fd.close()

    if not os.path.isdir(out + '/err'):
        os.makedirs(out + '/err')
    manager.V('state')

    shutil.copyfile(out + '/.input_{}.si'.format(proc_num),
                    out + '/err/err_{}_{}.si'.format(status, proc_num))


def isa_timeout(out, stop, proc_num):
    if not os.path.isdir(out + '/isa_timeout'):
        os.makedirs(out + '/isa_timeout')

    shutil.copy(out + '/.input_{}.elf'.format(proc_num), out + '/isa_timeout/timeout.elf')
    shutil.copy(out + '/.input_{}.S'.format(proc_num), out + '/isa_timeout/timeout.S')

    ps = psutil.Process()
    children = ps.children(recursive=True)
    for child in children:
        try: os.kill(child.pid, signal.SIGKILL) # SIGKILL
        except: continue

    stop[0] = proc_state.ERR_ISA_TIMEOUT

def run_isa_test(isaHost, isa_input, stop, out, proc_num, assert_intr=False):
    ret = proc_state.NORMAL
   
    timer = Timer(ISA_TIME_LIMIT, isa_timeout, [out, stop, proc_num])
    timer.start()
    isa_ret = isaHost.run_test(isa_input, assert_intr)
    timer.cancel()

    if stop[0] == proc_state.ERR_ISA_TIMEOUT:
        stop[0] = proc_state.NORMAL
        ret = proc_state.ERR_ISA_TIMEOUT
    elif isa_ret != 0:
        stop[0] = proc_state.ERR_ISA_ASSERT
        ret = proc_state.ERR_ISA_ASSERT

    return ret

def run_hsc_test(hscHost, hsc_input, stop, out, proc_num, assert_intr=False):#TODO adapt to sail: execute, perform check on 
    equal = hscHost.run_test(hsc_input)

    if not equal:
        return proc_state.ERR_ISA_ASSERT

    return proc_state.NORMAL

    # TODO maybe implement timeout stuff
    # timer = Timer(ISA_TIME_LIMIT, isa_timeout, [out, stop, proc_num])
    # timer.start()
    # isa_ret = isaHost.run_test(isa_input, assert_intr)
    # timer.cancel()

    # if stop[0] == proc_state.ERR_ISA_TIMEOUT:
    #     stop[0] = proc_state.NORMAL
    #     ret = proc_state.ERR_ISA_TIMEOUT
    # elif isa_ret != 0:
    #     stop[0] = proc_state.ERR_ISA_ASSERT
    #     ret = proc_state.ERR_ISA_ASSERT

    # return ret

def debug_print(message, debug, highlight=False):
    if highlight:
        print('\x1b[1;31m' + message + '\x1b[1;m')
    elif debug:
        print(message)

def save_file(file_name, mode, line):
    fd = open(file_name, mode)
    fd.write(line)
    fd.close()

def save_mismatch(base, proc_num, out, sim_input: simInput, data: Tuple[list, list], num): #, elf, asm, hexfile, mNum):
    sim_input.save(out + '/sim_input/id_{}.si'.format(num), data)

    asm_name_a = base + '/.input_{}_a.S'.format(proc_num)
    asm_name_b = base + '/.input_{}_b.S'.format(proc_num)
    elf_name_a = base + '/.input_{}_a.elf'.format(proc_num)
    elf_name_b = base + '/.input_{}_b.elf'.format(proc_num)
    hex_name = base + '/.input_{}.hex'.format(proc_num)

    shutil.copy(asm_name_a, out + '/asm/id_{}_a.S'.format(num))
    shutil.copy(asm_name_b, out + '/asm/id_{}_b.S'.format(num))
    shutil.copy(elf_name_a, out + '/elf/id_{}_a.elf'.format(num))
    shutil.copy(elf_name_b, out + '/elf/id_{}_b.elf'.format(num))
    shutil.copy(hex_name, out + '/hex/id_{}.hex'.format(num))

def setup(dut, toplevel, template, out, proc_num, debug, minimizing=False, no_guide=False):
    mutator = rvMutator(no_guide=no_guide)

    cc = 'riscv64-unknown-elf-gcc'
    elf2hex = 'riscv64-unknown-elf-elf2hex'
    preprocessor = rvPreProcessor(cc, elf2hex, template, out, proc_num)

    spike = os.environ['SPIKE']
    isa_sigfile = out + '/.isa_sig_{}.txt'.format(proc_num)
    rtl_sigfile = out + '/.rtl_sig_{}.txt'.format(proc_num)

    if debug: spike_arg = ['-l']
    else: spike_arg = []

    isaHost = rvISAhost(spike, spike_arg, isa_sigfile)
    rtlHost = rvRTLhost(dut, toplevel, rtl_sigfile, debug=debug)

    checker = sigChecker(isa_sigfile, rtl_sigfile, debug, minimizing)

    return (mutator, preprocessor, isaHost, rtlHost, checker)

def setupHSC(dut, toplevel, template, out, proc_num, debug, minimizing=False, no_guide=False): #TODO adapt to sail
    mutator = rvMutator(no_guide=no_guide)

    cc = 'riscv64-unknown-elf-gcc'
    elf2hex = 'riscv64-unknown-elf-elf2hex'
    preprocessor = rvPreProcessor(cc, elf2hex, template, out, proc_num)

    sail = os.environ['SAIL']
    hsc_outfiles = (out + '/.hsc_out_{}_a.txt'.format(proc_num), out + '/.hsc_out_{}_b.txt'.format(proc_num))
    rtl_sigfile = out + '/.rtl_sig_{}.txt'.format(proc_num)

    if debug: sail_arg = []
    else: sail_arg = ['-V']

    sail_arg += ['-L', 'ct'] #TODO make contract an input argument
    #sail_arg += ['-L', 'arch']

    hscHost = rvHSChost(sail, sail_arg, hsc_outfiles, debug=debug)
    rtlHost = rvRTLhost(dut, toplevel, rtl_sigfile, debug=debug)

    checker = sigChecker(hsc_outfiles, rtl_sigfile, debug, minimizing)

    return (mutator, preprocessor, hscHost, rtlHost, checker)