import sys
import os
import subprocess
import filecmp
from threading import Timer
import psutil
import signal
from src.multicore_manager import proc_state

HSC_TIME_LIMIT = 1 #time in seconds

class hscInput():
    def __init__(self, binary_a, binary_b, max_cycles=0): #GG now with two binaries
        self.binary_a = binary_a
        self.binary_b = binary_b
        self.max_cycles = max_cycles

class rvHSChost():
    def __init__(self, sail, sail_args, hsc_outfiles ,debug=False):
        self.sail = sail
        self.sail_args = sail_args
        (self.out_a, self.out_b) = hsc_outfiles
        self.debug = debug

    def debug_print(self, message):
        if self.debug:
            print(message)

    def timeout(self, stop):
        ps = psutil.Process()
        children = ps.children(recursive=True)
        for child in children:
            try: os.kill(child.pid, signal.SIGKILL) # SIGKILL
            except: continue

        stop[0] = proc_state.ERR_HSC_TIMEOUT

    def run_test(self, hsc_input: hscInput, stop):
        sail_args = [ self.sail ] + self.sail_args 
        if hsc_input.max_cycles > 0:
            sail_args += [ '-l {}'.format(hsc_input.max_cycles) ]

        self.debug_print('[HSCHost] Start contract checking')     
        args_a = sail_args + [ hsc_input.binary_a, '-o', self.out_a]
        # timer = Timer(HSC_TIME_LIMIT, self.timeout, [stop])
        # timer.start()
        a_ret = subprocess.call(args_a) #TODO parallelize with other call for b
        # timer.cancel()
        
        # if stop[0] == proc_state.ERR_HSC_TIMEOUT:
        #     stop[0] = proc_state.NORMAL
        #     return proc_state.ERR_HSC_TIMEOUT
        # el
        if a_ret != 0:
            return proc_state.ERR_HSC_ASSERT

        args_b = sail_args + [ hsc_input.binary_b, '-o', self.out_b]
        # timer = Timer(HSC_TIME_LIMIT, self.timeout, [stop])
        # timer.start()
        b_ret = subprocess.call(args_b)
        # timer.cancel()

        # if stop[0] == proc_state.ERR_HSC_TIMEOUT:
        #     stop[0] = proc_state.NORMAL
        #     return proc_state.ERR_HSC_TIMEOUT
        # el
        if b_ret != 0:
            return proc_state.ERR_HSC_ASSERT

        if filecmp.cmp(self.out_a, self.out_b, shallow=False):
            return proc_state.NORMAL
        else:
            return proc_state.ERR_CONTR_DIST
