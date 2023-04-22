import os
from cocotb.decorators import coroutine
from RTLSim.host import NO_LEAK, TIME_OUT, LEAK, rtlInput, rvRTLhost

from src.run_utils import *

@coroutine
def Run(dut, toplevel, input=None, debug=False):
    #start = time.perf_counter()
    assert toplevel in ['RocketTile', 'BoomTile' ], \
        '{} is not toplevel'.format(toplevel)
    
    (sim_input, (data_a, data_b), assert_intr) = read_siminput(input)

    max_cycles = 6000
    if sim_input.get_template() in [ V_U ]:
        max_cycles = 200000

    dir, fname = os.path.split(input)
    fname = fname.split('.si')[0]
    hex_name = os.path.join(dir, fname + '.hex')

    symbols_name = os.path.join(dir, fname + '.symbols')
    symbols = get_symbols(symbols_name)

    rtl_input = rtlInput(hex_name, None, data_a, data_b, symbols, max_cycles)

    rtlHost = rvRTLhost(dut, toplevel, None, debug=debug)

    #start_sim = time.perf_counter()
    try:
        (ret, (cov_bits, cov_map)) = yield rtlHost.run_test(rtl_input, assert_intr)
    except Exception as e:
        debug_print('[RTLHost] exception {}'.format(e), debug, True)

    #end_sim = time.perf_counter()

    if ret == LEAK: #not match or ret not in [NO_LEAK, ILL_MEM]:
        # if record:
        #     save_mismatch(out, proc_num, out + '/leaks',
        #                     sim_input, (data_a, data_b), lNum)

        debug_print('[HSCFuzz] Bug [Leakage]', debug, True)
        
    elif ret == TIME_OUT:
        # if record:
        #     save_mismatch(out, proc_num, out + '/rtl_timeout',
        #                     sim_input, (data_a, data_b), rtNum)

        debug_print('[HSCFuzz] Bug [RTL Timeout]', debug, True)
        
        # output coverage somehow

    cov_name = fname + '.cov'
    cov_out =  os.path.join(dir, cov_name)
    fd = open(cov_out, 'wb')
    cov_map.tofile(fd)
    fd.close()
    #end = time.perf_counter()
    #debug_print('[HSCFuzz] Init time {}'.format(start_sim - start), True)
    #debug_print('[HSCFuzz] RTLSim time {}'.format(end_sim - start_sim), True)
    #debug_print('[HSCFuzz] Output time {}'.format(end - end_sim), True)
    debug_print('[HSCFuzz] Stop Fuzzing, total {} cov_points'.format(cov_map.count(1)), debug)


