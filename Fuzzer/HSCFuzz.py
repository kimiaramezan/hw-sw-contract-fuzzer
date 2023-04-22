import os
import time
import signal
from datetime import datetime
import argparse

from src.utils import save_file
from src.multicore_manager import proc_state, procManager

from Fuzzer import Fuzz
from Minimizer import Minimize
from Replay import Replay

### Multicore Fuzzing ###

def wait_check(proc_pid_arr: list, manager: procManager):
    end_pid, exit_code = os.waitpid(0, 0)
    idx = proc_pid_arr.index(end_pid)

    if exit_code != 0:
        print('[HSCFuzz] Something bad happens! exit_code: {}'.format(exit_code))
        for pid in proc_pid_arr:
            if pid != end_pid:
                os.kill(pid, signal.SIGKILL)
        exit(-1)

    state = manager.get_state(idx)
    if state != proc_state.NORMAL:
        print('[HSCFuzz] Child {} is in abnormal state {}!'.format(idx, proc_state.tpe[state]))
        for pid in proc_pid_arr:
            if pid != end_pid:
                os.kill(pid, signal.SIGKILL)
        exit(-1)

    return idx

#########################

""" Fuzzer entry """
parser = argparse.ArgumentParser(prog="HSCFuzz",
                                 description="Fuzz RTL designs against HW-SW contracts")

parser.add_argument('-t', '--target', help='DUT: Rocket/BOOM')
parser.add_argument('-c', '--contract', default='ct', help='HW-SW contract to check')
parser.add_argument('-i', '--isa', default='RV64I', help='RISC-V ISA subset to use')
parser.add_argument('-n', '--num_iter', type=int, help='The number of fuzz iterations')
parser.add_argument('-o', '--output', help='Directory to save the result')
parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
parser.add_argument('-r', '--replay', default=None, help='SimInput to replay')
parser.add_argument('-m', '--multi', type=int, default=0, help='Maximal number of parallel simulators')
parser.add_argument('--minimize', action='store_true', help='Replay and minimize')
parser.add_argument('--no_guide', help='Random testing')

args = parser.parse_args()

out = args.output
# record = parser.arg_map['record'][0]
# replay = parser.arg_map['replay'][0]
# multicore = min(parser.arg_map['multicore'][0], 40)
# minimize = parser.arg_map['minimize'][0]
# parser.arg_map.pop('minimize', None)


# template = parser.arg_map['template'][0]
# debug = parser.arg_map['debug'][0]
# contract = parser.arg_map['contract'][0]
# isa = parser.arg_map['isa'][0]

if args.replay:
    Replay(args.target, in_file=args.replay, contract=args.contract, debug=args.verbose)
else:
    if not os.path.isdir(out):
        os.makedirs(out)

    if not os.path.isdir(out + '/leaks'):
        os.makedirs(out + '/leaks')
        os.makedirs(out + '/leaks/sim_input')
        os.makedirs(out + '/leaks/elf')
        os.makedirs(out + '/leaks/asm')
        os.makedirs(out + '/leaks/hex')

    if not os.path.isdir(out + '/illegal'):
        os.makedirs(out + '/illegal')
        os.makedirs(out + '/illegal/sim_input')
        os.makedirs(out + '/illegal/elf')
        os.makedirs(out + '/illegal/asm')
        os.makedirs(out + '/illegal/hex')

    if not os.path.isdir(out + '/hsc_timeout'):
        os.makedirs(out + '/hsc_timeout')
        os.makedirs(out + '/hsc_timeout/sim_input')
        os.makedirs(out + '/hsc_timeout/elf')
        os.makedirs(out + '/hsc_timeout/asm')
        os.makedirs(out + '/hsc_timeout/hex')

    if not os.path.isdir(out + '/rtl_timeout'):
        os.makedirs(out + '/rtl_timeout')
        os.makedirs(out + '/rtl_timeout/sim_input')
        os.makedirs(out + '/rtl_timeout/elf')
        os.makedirs(out + '/rtl_timeout/asm')
        os.makedirs(out + '/rtl_timeout/hex')

    if not os.path.isdir(out + '/contr_dist'):
        os.makedirs(out + '/contr_dist')
        os.makedirs(out + '/contr_dist/sim_input')
        os.makedirs(out + '/contr_dist/elf')
        os.makedirs(out + '/contr_dist/asm')
        os.makedirs(out + '/contr_dist/hex')

    if not os.path.isdir(out + '/corpus'):
        os.makedirs(out + '/corpus')

    if not os.path.isdir(out + '/trace'):
        os.makedirs(out + '/trace')

    date = datetime.today().strftime('%Y%m%d')
    cov_log = out + '/cov_log_{}.txt'.format(date)
    if not os.path.isfile(cov_log):
        save_file(cov_log, 'w', '{:<10}\t{:<10}\t{:<10}\t{:<10}\n'.
                format('time', 'iter', 'new_bits', 'cov_bits'))
        
    # if replay:
    #     trace_log = out + '/trace_replay_{}.txt'.format(date)
    #     if not os.path.isfile(trace_log):
    #         save_file(trace_log, 'w', '{:<10}\t{:<10}\t{:<10}\t{:<10}\n'.
    #                     format('time', 'iter', 'new_bits', 'cov_bits'))
    # else:
    trace_log = out + '/trace_log_{}.txt'.format(date)
    if not os.path.isfile(trace_log):
        save_file(trace_log, 'w', '{:<10}\t{:<10}\t{:<10}\t{:<10}\n'.
                format('time', 'iter', 'new_bits', 'cov_bits'))

    if args.minimize:
        Minimize(args.target, out=out, contract=args.contract, isa=args.isa, debug=args.verbose) 
    else:
        Fuzz(args.target, num_iter=args.num_iter, out=out, cov_log=cov_log,
            contract=args.contract, isa=args.isa, trace_log=trace_log, 
            debug=args.verbose, cores=args.multi)