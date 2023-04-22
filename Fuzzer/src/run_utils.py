from inst_generator import Word, PREFIX, MAIN, SUFFIX
from mutator import simInput

def debug_print(message, debug, highlight=False):
    if highlight:
        print('\x1b[1;31m' + message + '\x1b[1;m')
    elif debug:
        print(message)


""" Template versions """
P_M = 0
P_S = 1
P_U = 2

# V_M = 3
# V_S = 3
V_U = 3

templates = [ 'p-m', 'p-s', 'p-u',
              'v-u']


def read_siminput(si_name):
    fd = open(si_name, 'r')
    lines = fd.readlines()
    fd.close()

    ints = []
    prefix_tuples = []
    word_tuples = []
    suffix_tuples = []
    data = ([],[])

    num_prefix = 0
    num_word = 0
    num_suffix = 0

    part = None
    tmp_tuples = None
    num_tmp = None

    template_word = lines.pop(0).split('\n')[0]
    template = templates.index(template_word)
    lines.pop(0)
    while True:
        try: line = lines.pop(0)
        except: break

        if 'data_a:' in line:
            part = None
            while True:
                try: word = lines.pop(0)
                except: break
                if not 'data_b:' in word:
                    data[0].append(int(word, 16))
                else:
                    while True:
                        try: word = lines.pop(0)
                        except: break
                        data[1].append(int(word, 16))
                    break
            break
        elif line[:2] == PREFIX:
            part = PREFIX
            num_prefix += 1
            tmp_tuples = read_label(line, prefix_tuples)
            num_tmp = num_prefix

            tmp_tuples[num_tmp - 1][1].append(line[8:50])
        elif line[:2] == MAIN:
            part = MAIN
            num_word += 1
            tmp_tuples = read_label(line, word_tuples)
            num_tmp = num_word
            
            tmp_tuples[num_tmp - 1][1].append(line[8:50])
        elif line[:2] == SUFFIX:
            part = SUFFIX
            num_suffix += 1
            tmp_tuples = read_label(line, suffix_tuples)
            num_tmp = num_suffix

            tmp_tuples[num_tmp - 1][1].append(line[8:50])
        else:
            tmp_tuples[num_tmp - 1][1].append(line[8:50])

        if part == MAIN:
            ints.append(int(line[-5:-1], 2))

    prefix = tuples_to_words(prefix_tuples, PREFIX)
    words = tuples_to_words(word_tuples, MAIN)
    suffix = tuples_to_words(suffix_tuples, SUFFIX)

    sim_input = simInput(prefix, words, suffix, ints, 0, template)

    assert_intr = False
    if [ i for i in ints if i != 0 ]:
        assert_intr = True

    return (sim_input, data, assert_intr)


def read_label(line, tuples):
    label = line[:8].split(':')[0]
    label_num = int(label[2:])

    insts = []
    tuples.append((label_num, insts))

    return tuples

def tuples_to_words(tuples, part):
    words = []

    for tup in tuples:
        label = tup[0]
        insts = tup[1]

        word = Word(label, insts)
        word.populate({}, part)

        words.append(word)

    return words

def get_symbols(sym_name):
    # symbol_file = self.base + '/.input.symbols'

    symbols = {}
    fd = open(sym_name, 'r')
    lines = fd.readlines()
    fd.close()

    for line in lines:
        symbol = line.split(' ')[2]
        addr = line.split(' ')[0]
        symbols[symbol[:-1]] = int(addr, 16)

    return symbols