from enum import Enum
ROCKET_CONF = ('RocketTile', '~/experiment_4/fuzz_bin', 'rocket_tile_inst_reset', 1730)
BOOM_CONF = ('BoomTile', '~/experiment_4/fuzz_bin_boom', 'boom_cov_reset', 18808)

class Feedback(Enum):
    COVERAGE_FB = 0
    PASS_FB = 1
    NO_FB = 2

FEEDBACK = Feedback.COVERAGE_FB

DATA_EQ_REGISTERS = True
DATA_GUIDANCE = False
DATA_50_50 = True

