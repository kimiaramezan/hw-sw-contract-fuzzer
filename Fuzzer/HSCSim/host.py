import sys
import os
import subprocess
import filecmp

class hscInput():
    def __init__(self, binary_a, binary_b): #GG now with two binaries
        self.binary_a = binary_a
        self.binary_b = binary_b

class rvHSChost():  #TODO adapt to sail simulator
    def __init__(self, sail, sail_args, hsc_outfiles ,debug=False):
        self.sail = sail
        self.sail_args = sail_args
        (self.out_a, self.out_b) = hsc_outfiles
        self.debug = debug

    def debug_print(self, message):
        if self.debug:
            print(message)

    def run_test(self, hsc_input: hscInput):
        self.debug_print('[ISAHost] Start ISA simulation')        
        args = [ self.sail ] + self.sail_args + \
            [ hsc_input.binary_a, '-o', self.out_a]
        subprocess.call(args)
        args = [ self.sail ] + self.sail_args + \
            [ hsc_input.binary_b, '-o', self.out_b]    
        subprocess.call(args)

        return filecmp.cmp(self.out_a, self.out_b, shallow=False)
