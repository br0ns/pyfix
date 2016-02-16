from fix import fix

import math

# Used as a decorator: x is initially 0
@fix(0)
def x(f = math.cos):
    x = f(x)

print x

# Called directly, the initial value must be given as a keyword argument
def x():
    x = math.cos(x)

print fix(x, init = 0)

# Self referential sentences, yay!

from num2words import num2words

@fix
def sentence():
    return 'This sentence is %s characters long!' % \
        num2words(len(sentence or ''))
print(sentence)

# Almost equivalent:
@fix('')
def sentence():
    sentence = 'This sentence is %s characters long!' % \
        num2words(len(sentence))
print(sentence)

# This is the use case I originally had in mind

from pwnlib.util.packing import flat

pop_rdi = 0x40000
puts    = 0x40000
base    = 0x40000
@fix
def rop2(end = 0):
    rop2 = flat(pop_rdi, end, puts)
    end = base + len(rop2)
    rop2 += "/bin/sh\x00"

print `rop2`
