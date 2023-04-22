import os
import math
from copy import deepcopy
import tempfile

from RTLSim.host import NO_LEAK, TIME_OUT, LEAK
from src.word import PREFIX, MAIN, SUFFIX

from src.utils import *
from src.multicore_manager import proc_state

ROCKET_CONF = ('RocketTile', '~/Documents/fuzz_bin_rocket', 'rocket_tile_inst_reset')
BOOM_CONF = ('BoomTile', '~/Documents/fuzz_bin', 'boom_cov_reset')

def Replay(target, in_file=None,
             template='Template', proc_num=0,
             debug=False, contract='ct', isa='RV64IM'):
    with tempfile.TemporaryDirectory() as out:
        assert target in ['Rocket', 'Boom' ], \
            '{} is not toplevel'.format(target)
        proc_num = 0

        if target == 'Rocket':
            toplevel, bin_dir, v_file = ROCKET_CONF
        else:
            toplevel, bin_dir, v_file = BOOM_CONF



        (mutator, preprocessor, hscHost) = \
            setupHSC(template, out, proc_num, debug, contract, isa)

        (sim_input, (data_a, data_b), assert_intr) = mutator.read_siminput(in_file)

        (isa_input, rtl_input, symbols) = preprocessor.process(sim_input, data_a, data_b, assert_intr)
        
        stop = [ proc_state.NORMAL ]
        ret = hscHost.run_test(isa_input, stop)
        if ret == proc_state.ERR_HSC_TIMEOUT:
            print('[Replay] {} leads to Sail timeout'.format(in_file)) # this should not happen as execution time with no-ops should be lower
            return
        if ret == proc_state.ERR_CONTR_DIST:
            print('[Replay] {} is contract distinguishable'.format(in_file))# this should not happen as replacing a command with no-ops should lead to less leakage
            return
        if ret == proc_state.ERR_HSC_ASSERT: # this should not happen as replacing a command with no-ops should not lead to faults
            print('[Replay] {} leads to Sail non-zero exit'.format(in_file))
            return
        
        (ret, cov_map, _, _) = run_rtl_test(bin_dir, v_file, toplevel, rtl_input, 0, None)

        if ret == ERROR:
            debug_print('[RTLHost] exception {}'.format(e), debug, True)

        elif ret == LEAK: #not match or ret not in [NO_LEAK, ILL_MEM]:
            debug_print('[HSCFuzz] Bug [Leakage]', debug, True)
            
        elif ret == TIME_OUT:
            debug_print('[HSCFuzz] Bug [RTL Timeout]', debug, True)
                
        print('[HSCFuzz] Stop Fuzzing, total {} cov_points'.format(cov_map.count(1)))
