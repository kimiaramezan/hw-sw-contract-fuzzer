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
def Run(dut, toplevel,
        num_iter=1, template='Template', in_file=None,
        out='output', record=False, cov_log=None,
        multicore=0, manager=None, proc_num=0, start_time=0, start_iter=0, start_cov=0,
        prob_intr=0, no_guide=False, debug=False, contract='ct', isa='RV64I'):

    assert toplevel in ['RocketTile', 'BoomTile' ], \
        '{} is not toplevel'.format(toplevel)

    random.seed(time.time() * (proc_num + 1))

    (mutator, preprocessor, hscHost, rtlHost, checker) = \
        setupHSC(dut, toplevel, template, out, proc_num, debug, contract, isa, no_guide=no_guide)

    if in_file: num_iter = 1

    stop = [ proc_state.NORMAL ]
    lNum = 0
    cNum = 0
    rtNum = 0
    htNum = 0
    cdNum = 0
    last_coverage = bitarray(repeat(0,1730)) #TODO adapt to toplevel design

    debug_print('[DifuzzRTL] Start Fuzzing', debug)

    if multicore:
        yield manager.cov_restore(dut)

    for it in range(num_iter):
        debug_print('[DifuzzRTL] Iteration [{}]'.format(it), debug)

        if multicore:
            if it == 0:
                mutator.update_corpus(out + '/corpus', 1000)
            elif it % 1000 == 0:
                mutator.update_corpus(out + '/corpus')

        assert_intr = False
        if random.random() < prob_intr:
            assert_intr = True

        if in_file: (sim_input, (data_a, data_b), assert_intr) = mutator.read_siminput(in_file)
        else: (sim_input, (data_a, data_b)) = mutator.get(assert_intr)

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
            #     debug_print('[DifuzzRTL] Memory access outside DRAM -- {}'. \
            #                 format(iNum), debug, True)
            #     if record:
            #         save_mismatch(out, proc_num, out + '/illegal',
            #                       sim_input, (data_a, data_b), iNum)
            #     iNum += 1

            if ret == LEAK: #not match or ret not in [NO_LEAK, ILL_MEM]:
                if multicore:
                    lNum = manager.read_num('lNum')
                    manager.write_num('lNum', lNum + 1)

                if record:
                    save_mismatch(out, proc_num, out + '/leaks',
                                  sim_input, (data_a, data_b), lNum)

                lNum += 1

                debug_print('[DifuzzRTL] Bug -- {} [Leakage]'. \
                            format(lNum), debug, True)
                
            elif ret == TIME_OUT:
                if multicore:
                    rtNum = manager.read_num('rtNum')
                    manager.write_num('rtNum', rtNum + 1)

                if record:
                    save_mismatch(out, proc_num, out + '/rtl_timeout',
                                  sim_input, (data_a, data_b), rtNum)

                rtNum += 1
                debug_print('[DifuzzRTL] Bug -- {} [RTL Timeout]'. \
                            format(rtNum), debug, True)
            
            cov_bits = int2ba(cov_bits, length=1730, endian='big')
            cov_bits = ~cov_bits #change to 1 indicating a difference
            new_coverage = ~last_coverage & cov_bits
            debug_print("new_cov:{}".format(new_coverage), debug, False)
            debug_print("new_cov#:{}".format(new_coverage.count(1)), debug, False)
            if new_coverage.any():
                if multicore:
                    cNum = manager.read_num('cNum')
                    manager.write_num('cNum', cNum + 1)

                if record:
                    coverage = new_coverage.count(1)
                    save_file(cov_log, 'a', '{:<10}\t{:<10}\t{:<10}\t{:<10}\n'.
                              format(time.time() - start_time, start_iter + it,
                                     start_cov + coverage, cov_bits.count(1)))
                    sim_input.save(out + '/corpus/id_{}.si'.format(cNum))

                cNum += 1
                mutator.add_corpus(sim_input)
                last_coverage = last_coverage | cov_bits

            mutator.update_phase(it)

        else:
            stop[0] = proc_state.ERR_COMPILE
            # Compile failed
            break

    if multicore:
        save_err(out, proc_num, manager, stop[0])
        manager.set_state(proc_num, stop[0])

    debug_print('[DifuzzRTL] Stop Fuzzing', debug)

    if multicore:
        yield manager.cov_store(dut, proc_num)
        manager.store_covmap(proc_num, start_time, start_iter, num_iter)
