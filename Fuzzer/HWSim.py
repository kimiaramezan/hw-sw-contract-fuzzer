from cocotb.regression import TestFactory

from src.env_parser import envParser

from Runner import Run

""" Simulator entry """
parser = envParser()

parser.add_option('toplevel', None, 'Toplevel module of DUT')
parser.add_option('input', None, 'SimInput to simulate')
parser.add_option('debug', 0, 'Debugging?')

parser.print_help()
parser.parse_option()

factory = TestFactory(Run)
parser.register_option(factory)

factory.generate_tests()
