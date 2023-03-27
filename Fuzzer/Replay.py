from itertools import repeat
import time
import random
from bitarray import bitarray
from bitarray.util import int2ba

from cocotb.decorators import coroutine
from RTLSim.host import NO_LEAK, TIME_OUT, LEAK

from src.utils import *
from src.multicore_manager import proc_state


@coroutine
def Replay(dut, toplevel, template='Template', out='output', cov_log=None,
        proc_num=0, start_time=0, start_iter=0, start_cov=0, replay=0,
        no_guide=False, debug=True, contract='ct', isa='RV64I', trace_log=None):

    assert toplevel in ['RocketTile', 'BoomTile' ], \
        '{} is not toplevel'.format(toplevel)

    random.seed(time.time() * (proc_num + 1))

    (mutator, preprocessor, hscHost, rtlHost, checker) = \
        setupHSC(dut, toplevel, template, out, proc_num, debug, contract, isa, no_guide=no_guide)

    stop = [ proc_state.NORMAL ]
    lNum = 0
    cNum = 0
    rtNum = 0
    htNum = 0
    cdNum = 0
    last_coverage = bitarray(repeat(0,1730)) #TODO adapt to toplevel design

    debug_print('[DifuzzRTL] Start Fuzzing', debug)

    in_dir = os.path.join(out, 'trace')
    in_files = [f for f in os.listdir(in_dir) if os.path.isfile(os.path.join(in_dir, f))] 
    in_files.sort(key=lambda x: int(x.split('_')[1].split('.')[0]))
    for in_file in in_files[:replay]:
        debug_print('[DifuzzRTL] Replay [{}]'.format(in_file), debug)

        #assert_intr = False
        #if random.random() < prob_intr: GG if interrupts are introduced this must be adapted to equal the fuzz execution
        #    assert_intr = True

        (sim_input, (data_a, data_b), assert_intr) = mutator.read_siminput(os.path.join(in_dir, in_file))

        if debug:
            print('[DifuzzRTL] Fuzz Instructions')
            for inst, INT in zip(sim_input.get_insts(), sim_input.ints + [0]):
                print('{:<50}{:04b}'.format(inst, INT))

        (hsc_input, rtl_input, symbols) = preprocessor.process(sim_input, data_a, data_b, assert_intr)

        if hsc_input and rtl_input:
            ret = hscHost.run_test(hsc_input, stop)
            if ret == proc_state.ERR_HSC_TIMEOUT: 
                save_mismatch(out, proc_num, out + '/hsc_timeout',
                                  sim_input, (data_a, data_b), htNum)
                htNum += 1
                debug_print('[HSCHost] timeout', debug, True)
                continue
            elif ret == proc_state.ERR_CONTR_DIST: 
                save_mismatch(out, proc_num, out + '/contr_dist',
                                  sim_input, (data_a, data_b), cdNum)
                cdNum += 1
                debug_print('[HSCHost] contract distinguishable', debug, True)
                continue
            elif ret == proc_state.ERR_HSC_ASSERT: # exit, temporary files stay available to debug sail
                debug_print('[HSCHost] non-zero exit code', debug, True)
                break

            try:
                (ret, (cov_bits, cov_map)) = yield rtlHost.run_test(rtl_input, assert_intr)
            except Exception as e:
                debug_print('[RTLHost] exception {}'.format(e), debug, True)
                stop[0] = proc_state.ERR_RTL_SIM
                break

            if ret == LEAK: #not match or ret not in [NO_LEAK, ILL_MEM]:
 
                lNum += 1

                debug_print('[DifuzzRTL] Bug -- {} [Leakage]'. \
                            format(lNum), debug, True)
                
            elif ret == TIME_OUT:

                rtNum += 1
                debug_print('[DifuzzRTL] Bug -- {} [RTL Timeout]'. \
                            format(rtNum), debug, True)
            
            cov_bits = int2ba(cov_bits, length=1730, endian='big')
            cov_bits = ~cov_bits #change to 1 indicating a difference
            new_coverage = ~last_coverage & cov_bits
            coverage = new_coverage.count(1)
            
            debug_print("new_cov:{}".format(new_coverage), debug, False)
            debug_print("new_cov#:{}".format(new_coverage.count(1)), debug, False)
                        
            save_file(trace_log, 'a', '{:<10}\t{:<10}\t{:<10}\t{:<10}\n'.format(
                time.time() - start_time, in_file, coverage, cov_bits.count(1)))

            if new_coverage.any():

                cNum += 1
                mutator.add_corpus(sim_input)
                last_coverage = last_coverage | cov_bits


        else:
            stop[0] = proc_state.ERR_COMPILE
            # Compile failed
            break

    debug_print('[DifuzzRTL] Stop Fuzzing', debug)
