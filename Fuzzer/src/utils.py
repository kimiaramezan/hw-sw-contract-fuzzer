import os
import shutil
import subprocess
import sys
from typing import Tuple
from bitarray import bitarray
import psutil
import signal
from threading import Timer

from HSCSim.host import rvHSChost
from RTLSim.host import rvRTLhost

from src.preprocessor import rvPreProcessor
from src.signature_checker import sigChecker
from src.mutator import simInput, rvMutator
from src.multicore_manager import proc_state, procManager

ISA_TIME_LIMIT = 1

NO_LEAK = 0
LEAK = 1
TIME_OUT = 2
ERROR = 3

def save_err(out: str, proc_num: int, manager: procManager, stop_code: int):

    if stop_code == proc_state.NORMAL:
        return

    status = proc_state.tpe[stop_code]

    manager.P('state')
    fd = open(out + '/fuzz_log', 'a')
    fd.write('[HSCFuzz] Thread {}: {} occurred\n'.format(proc_num, status))
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
        stop[0] = proc_state.ERR_HSC_ASSERT
        ret = proc_state.ERR_HSC_ASSERT

    return ret

def debug_print(message, debug, highlight=False):
    if highlight:
        print('\x1b[1;31m' + message + '\x1b[1;m')
    elif debug:
        print(message)

def save_file(file_name, mode, line):
    fd = open(file_name, mode)
    fd.write(line)
    fd.close()

def save_mismatch(base, out, id, bug_id): #, elf, asm, hexfile, mNum):
    # sim_input.save(out + '/sim_input/id_{}.si'.format(num), data)

    shutil.copy(os.path.join(base, '.input_{}.si'.format(id)), out + '/sim_input/id_{}.si'.format(bug_id))
    # asm_name_a = base + '/.input_{}_a.S'.format(proc_num)
    # asm_name_b = base + '/.input_{}_b.S'.format(proc_num)
    # elf_name_a = base + '/.input_{}_a.elf'.format(proc_num)
    # elf_name_b = base + '/.input_{}_b.elf'.format(proc_num)
    # hex_name = base + '/.input_{}.hex'.format(proc_num)

    # shutil.copy(asm_name_a, out + '/asm/id_{}_a.S'.format(num))
    # shutil.copy(asm_name_b, out + '/asm/id_{}_b.S'.format(num))
    # shutil.copy(elf_name_a, out + '/elf/id_{}_a.elf'.format(num))
    # shutil.copy(elf_name_b, out + '/elf/id_{}_b.elf'.format(num))
    # shutil.copy(hex_name, out + '/hex/id_{}.hex'.format(num))

def save_leak(base, out, id, bug_id): #, elf, asm, hexfile, mNum):
    # sim_input.save(out + '/sim_input/id_{}.si'.format(num), data)

    shutil.copy(os.path.join(base, '.input_{}.si'.format(id)), out + '/sim_input/id_{}.si'.format(bug_id))
    shutil.copy(os.path.join(base, '.input_{}.cov'.format(id)), out + '/sim_input/id_{}.cov'.format(bug_id))


def setupHSC(template, out, proc_num, debug, contract='ct', isa='RV64I', no_guide=False):
    mutator = rvMutator(isa, no_guide=no_guide)

    cc = 'riscv64-unknown-elf-gcc'
    elf2hex = 'riscv64-unknown-elf-elf2hex'
    preprocessor = rvPreProcessor(cc, elf2hex, template, out, proc_num)

    sail = os.environ['SAIL']
    hsc_outfiles = (out + '/.hsc_out_{}_a.txt'.format(proc_num), out + '/.hsc_out_{}_b.txt'.format(proc_num))
    # rtl_sigfile = out + '/.rtl_sig_{}.txt'.format(proc_num)

    if debug: sail_arg = ['-v'] # [] change for sail debug output
    else: sail_arg = ['-V', '-vplatform']

    sail_arg += ['-L', contract] # use contract from input argument

    hscHost = rvHSChost(sail, sail_arg, hsc_outfiles, debug=debug)
    # rtlHost = rvRTLhost(dut, toplevel, rtl_sigfile, debug=debug)

    # checker = sigChecker(hsc_outfiles, rtl_sigfile, debug, minimizing)

    return (mutator, preprocessor, hscHost)

# from hashlib import shake_128

def run_rtl_test(bin_dir, v_file, toplevel, sim_input_name, id, sim_input):
    
    res_file = 'results_{}.xml'.format(id)

    debug = 0
    cmd = 'make SIM_BUILD={} VFILE={} TOPLEVEL={} DEBUG={} INPUT={} COCOTB_RESULTS_FILE={}'.format(bin_dir, v_file, toplevel, debug, sim_input_name, res_file)
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=sys.stdout.fileno())

    leak = any(filter(lambda x: '[Leakage]' in str(x), p.stdout.splitlines()))
    # if debug == 1:
    #     temp = b''
    #     for l in filter(lambda x: "idx" in str(x),p.stdout.splitlines()):
    #         if l != temp:
    #             print(l)
    #             temp = l
    dir, fname = os.path.split(sim_input_name)
    fname = fname.split('.si')[0]
    cov_name = fname + '.cov'
    cov_out =  os.path.join(dir, cov_name)

    # fd = open(os.path.join(dir, fname + '.symbols'), 'rb')
    # ct = fd.read()
    # print(shake_128(ct).hexdigest(8))
    # fd = open(os.path.join(dir, fname + '.hex'), 'rb')
    # ct = fd.read()
    # print(shake_128(ct).hexdigest(8))

    b = bitarray()
    fd = open(cov_out, 'rb')
    b.fromfile(fd)
    fd.close()

    if leak:
        save_leak(dir, dir + '/leaks', id, id)


    os.remove(cov_out)
    os.remove(sim_input_name)
    os.remove(os.path.join(dir, fname + '_a.S'))
    os.remove(os.path.join(dir, fname + '_b.S'))
    os.remove(os.path.join(dir, fname + '_a.elf'))
    os.remove(os.path.join(dir, fname + '_b.elf'))
    os.remove(os.path.join(dir, fname + '.hex'))
    os.remove(os.path.join(dir, fname + '.symbols'))
    os.remove(os.path.join(os.getcwd(), res_file))

    return (LEAK if leak else NO_LEAK, b, id, sim_input) #TODO detect timeout and errors

def cleanup(sim_input_name):
    
    dir, fname = os.path.split(sim_input_name)
    fname = fname.split('.si')[0]

    os.remove(sim_input_name)
    os.remove(os.path.join(dir, fname + '_a.S'))
    os.remove(os.path.join(dir, fname + '_b.S'))
    os.remove(os.path.join(dir, fname + '_a.elf'))
    os.remove(os.path.join(dir, fname + '_b.elf'))
    os.remove(os.path.join(dir, fname + '.hex'))
    os.remove(os.path.join(dir, fname + '.symbols'))