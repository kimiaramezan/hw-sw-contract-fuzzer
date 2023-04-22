from concurrent.futures import ProcessPoolExecutor, as_completed
from itertools import repeat
import time
import random
from bitarray import bitarray
from bitarray.util import int2ba

from src.utils import *
from src.multicore_manager import proc_state


ROCKET_COV_LEN = 1730
BOOM_COV_LEN = 18808

ROCKET_CONF = ('RocketTile', '~/Documents/fuzz_bin_rocket', 'rocket_tile_inst_reset')
BOOM_CONF = ('BoomTile', '~/Documents/fuzz_bin', 'boom_cov_reset')

def Fuzz(target, num_iter=1, template='Template', in_file=None, debug=True, record=True,
        out='output', cov_log=None, contract='ct', isa='RV64I', trace_log=None, cores=0):
    
    assert target in ['Rocket', 'Boom' ], \
        '{} is not toplevel'.format(target)
    
    print('[HSCFuzz] Fuzzing {}, {} against {}, output to {}'.format(target, isa, contract, out))
    proc_num = 0
    start_time = time.time()

    if target == 'Rocket':
        toplevel, bin_dir, v_file = ROCKET_CONF
    else:
        toplevel, bin_dir, v_file = BOOM_CONF

    random.seed(time.time() * (proc_num + 1))

    (mutator, preprocessor, hscHost) = \
        setupHSC(template, out, proc_num, debug, contract, isa)

    if in_file: num_iter = 1

    stop = [ proc_state.NORMAL ]
    lNum = 0
    cNum = 0
    rtNum = 0
    htNum = 0
    cdNum = 0

    last_coverage = bitarray(repeat(0,2 ** 16))

    debug_print('[HSCFuzz] Start Fuzzing', debug)

    # number of submitted fuzzing jobs
    it = 0
    # number of retrieved fuzzing jobs
    rt = 0

    if cores == 0:
        cores = os.cpu_count()
    executor = ProcessPoolExecutor (max_workers=cores)

    futures = []

    while rt < num_iter:

        assert_intr = False
        # if random.random() < prob_intr:
        #     assert_intr = True

        while len(futures) < 32 and it < num_iter:

            (sim_input, (data_a, data_b)) = mutator.get(assert_intr)

            if debug:
                print('[HSCFuzz] Fuzz Instructions')
                for inst, INT in zip(sim_input.get_insts(), sim_input.ints + [0]):
                    print('{:<50}{:04b}'.format(inst, INT))

            (hsc_input, rtl_input, symbols) = preprocessor.process(sim_input, data_a, data_b, assert_intr, id=it)

            if hsc_input and rtl_input:
                ret = hscHost.run_test(hsc_input, stop)
                mutator.update_data_seed_energy(sim_input.get_seed(), ret==proc_state.ERR_CONTR_DIST)
                if ret == proc_state.ERR_HSC_TIMEOUT: 
                    save_mismatch(out, out + '/hsc_timeout', it, htNum)
                    htNum += 1
                    debug_print('[HSCHost] timeout', debug, True)
                    continue
                elif ret == proc_state.ERR_CONTR_DIST: 
                    save_mismatch(out, out + '/contr_dist', it, cdNum)
                    cdNum += 1
                    debug_print('[HSCHost] contract distinguishable', debug, True)
                    continue
                elif ret == proc_state.ERR_HSC_ASSERT: # exit, temporary files stay available to debug sail
                    debug_print('[HSCHost] non-zero exit code', debug, True)
                    break
                
                f = executor.submit(run_rtl_test, bin_dir, v_file, toplevel, rtl_input, it, sim_input)
                futures.append(f)
                it += 1
            mutator.update_phase(it)

        debug_print('[HSCFuzz] Iteration [{}]'.format(it), debug)
        for f in as_completed(futures):

            (ret, cov_map, run_id, run_input) = f.result()
            if ret == ERROR:
                debug_print('[RTLHost] exception {}'.format(run_id), debug, True)
                stop[0] = proc_state.ERR_RTL_SIM
                break
            
            #TODO maybe adapt to interrupts
            # if assert_intr and ret == NO_LEAK:
            #     (intr_prv, epc) = checker.check_intr(symbols)
            #     if epc != 0:
            #         preprocessor.write_isa_intr(hsc_input, rtl_input, epc)
            #         ret = run_isa_test(hscHost, hsc_input, stop, out, proc_num, True)
            #         if ret == proc_state.ERR_HSC_TIMEOUT: continue
            #         elif ret == proc_state.ERR_HSC_ASSERT: break
            #     else: continue

            # cause = '-'
            # match = False
            # if ret == NO_LEAK: #TODO compare sail vs rtl
            #    #match = checker.check(symbols)
            #    match = True
            # GG maybe add again if memory checks are interesting
            # elif ret == ILL_MEM: 
            #     match = True
            #     debug_print('[HSCFuzz] Memory access outside DRAM -- {}'. \
            #                 format(iNum), debug, True)
            #     if record:
            #         save_mismatch(out, proc_num, out + '/illegal',
            #                       sim_input, (data_a, data_b), iNum)
            #     iNum += 1

            elif ret == LEAK: #not match or ret not in [NO_LEAK, ILL_MEM]:
                if record:
                    save_leak(out, out + '/leaks', run_id, lNum)

                lNum += 1

                debug_print('[HSCFuzz] Bug #{}-- {} [Leakage]'. \
                            format(lNum, run_id), debug, True)
                
            elif ret == TIME_OUT:

                if record:
                    save_leak(out, out + '/rtl_timeout', run_id, rtNum)

                rtNum += 1
                debug_print('[HSCFuzz] Bug #{} -- {} [RTL Timeout]'. \
                            format(rtNum, run_id), debug, True)
            
            #leagacy fun stuff
            # cov_bits = int2ba(cov_bits, length=cov_len, endian='big')
            # cov_bits = ~cov_bits #change to 1 indicating a difference
            # old_cov_bits = cov_bits | old_cov_bits
            
            # real coverage parameters
            new_coverage = ~last_coverage & cov_map
            coverage = new_coverage.count(1)
            
            # debug_print("old_cov:{}".format(old_cov_bits.count(1)), debug, False)
            debug_print("new_cov#:{}".format(coverage), debug, False)
                        
            # sim_input.save(out + '/trace/id_{}.si'.format(rt), (data_a, data_b))
            if record:
                save_file(trace_log, 'a', '{:<10}\t{:<10}\t{:<10}\t{:<10}\n'.format(
                    time.time() - start_time, run_id, coverage, cov_map.count(1)))

            if new_coverage.any():
                if record:
                    save_file(cov_log, 'a', '{:<10}\t{:<10}\t{:<10}\t{:<10}\n'.
                              format(time.time() - start_time, run_id,
                                     coverage, cov_map.count(1)))
                    run_input.save(out + '/corpus/id_{}.si'.format(cNum))

                cNum += 1
                mutator.add_corpus(run_input)
                last_coverage = last_coverage | cov_map

            futures.remove(f)
            rt += 1
        
        debug_print('[HSCFuzz] Retrieving [{}]'.format(rt), debug)
        
        
    #TODO remove trace or move sim_inputs as trace saving
    print('[HSCFuzz] Stop Fuzzing, total {} cov_points'.format(last_coverage.count(1)))
