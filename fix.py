__all__ = ['fix']

import dis
import struct
import types
import sys

def enc_arg(arg):
    return struct.pack('<H', arg & 0xffff)

def dec_arg(arg):
    return struct.unpack('<H', arg)[0]

# Pseudo-opcode for branch targets
LABEL = None

# From Include/code.h
CO_GENERATOR = 0x0020

# This exception is raised if no fixed point is found within `max_iters`
# iterations
class DivergentError(Exception):
    pass

def pydis(code):
    n = len(code)
    i = 0
    extarg = 0
    ops = []

    # Find branch targets
    lbls = dis.findlabels(code)

    while i < n:
        # Insert label pseudo-instruction
        if i in lbls:
            ops.append((LABEL, lbls.index(i)))

        op = ord(code[i])
        i += 1
        if op >= dis.HAVE_ARGUMENT:
            arg = dec_arg(code[i : i + 2]) | extarg << 16
            extarg = 0
            i += 2
            if op == dis.EXTENDED_ARG:
                extarg = arg
                continue

            targ = None
            if op in dis.hasjrel:
                targ = i + arg
            elif op in dis.hasjabs:
                targ = arg

            if targ != None:
                arg = lbls.index(targ)

        else:
            arg = None

        ops.append((op, arg))

    return ops

def pyasm(code):
    lbls = dict()  # lbl -> addr
    targs = dict() # addr -> lbl, jump offset
    out = ''
    i = 0

    for op, arg in code:
        if op == LABEL:
            lbls[arg] = i
            continue
        addr = i

        i += 1
        if arg is None:
            out += chr(op)
        else:
            i += 2
            if arg >= 1 << 16:
                i += 3
                out += chr(dis.EXTENDED_ARG) + enc_arg(arg >> 16)
            out += chr(op) + enc_arg(arg)

        if op in dis.hasjrel:
            targs[addr] = (arg, i)
        elif op in dis.hasjabs:
            targs[addr] = (arg, 0)

    out = bytearray(out)
    for addr, (lbl, offset) in targs.items():
        targ = lbls[lbl] - offset
        out[addr + 1 : addr + 3] = enc_arg(targ)

    return str(out)

def fix_(init, func, max_iters):
    co = func.func_code
    argcount = co.co_argcount + 1
    self = co.co_name

    varnames = co.co_varnames
    names = co.co_names
    cellvars = co.co_cellvars

    code = pydis(co.co_code)
    lblstop = -1
    lblcont = -2
    lblret = -3
    consts = co.co_consts
    if True not in consts:
        consts = consts + (True,)
    if False not in consts:
        consts = consts + (False,)

    stacksize = max(co.co_stacksize, argcount + 1)

    # Make the function's name the first argument
    if self in varnames:
        self_var = varnames.index(self)
        varnames = varnames[:self_var] + varnames[self_var + 1:]
    else:
        self_var = None
    varnames = (self,) + varnames

    # If we never assign to the functions own name it will be a global or a cell
    if self in names:
        self_glob = names.index(self)
    else:
        self_glob = None

    # Op-codes to load self and each function argument; each may either be a
    # local variable or a cell reference
    load = []
    for i in xrange(argcount):
        var = varnames[i]
        if var in cellvars:
            op = dis.opmap['LOAD_DEREF']
            arg = cellvars.index(var)
        else:
            op = dis.opmap['LOAD_FAST']
            arg = i
        load.append((op, arg))

    i = 0
    while i < len(code):
        op, arg = code[i]

        # Re-number local variables and insert self as local var 0
        if op in dis.haslocal:
            if self_var == arg:
                arg = 0
            elif self_var is None or self_var > arg:
                arg += 1

        # Change global references to local ones
        if self_glob == arg:
            if op == dis.opmap['LOAD_GLOBAL']:
                op = dis.opmap['LOAD_FAST']
                # We know from the re-numbering that the function's own name is
                # the first local variable
                arg = 0
            # `STORE_GLOBAL` and `DELETE_GLOBAL` should only be possible with
            # the `global` keyword, which we will disallow
            if op in (dis.opmap['STORE_GLOBAL'],
                      dis.opmap['DELETE_GLOBAL']):
                raise ValueError('Variable \'%s\' must not be declared global' \
                                 % self)

        # Rewrite return statements to return the local state, i.e. self and the
        # function arguments.
        if op in (dis.opmap['RETURN_VALUE'],
                  dis.opmap['YIELD_VALUE']):
            prevop, prevarg = code[i - 1]
            # XXX: distinguish between `return` and `return None`.  Only the
            # former case should be rewritten to return self.
            if prevop == dis.opmap['LOAD_CONST'] and \
               consts[prevarg] == None:
                # Rewrite previous op-code to load self.
                code[i - 1] = load[0]

            # Jump to code at the end which loads and returns the local state
            arg = lblstop if op == dis.opmap['YIELD_VALUE'] else lblcont
            op = dis.opmap['JUMP_FORWARD']

        code[i] = (op, arg)
        i += 1

    tail = \
        [(LABEL, lblstop),
         (dis.opmap['LOAD_CONST'], consts.index(True)),
         (dis.opmap['JUMP_FORWARD'], lblret),
         (LABEL, lblcont),
         (dis.opmap['LOAD_CONST'], consts.index(False)),
         (LABEL, lblret),
         (dis.opmap['ROT_TWO'], None)] + \
        load[1:] + \
        [(dis.opmap['BUILD_TUPLE'], argcount + 1),
         (dis.opmap['RETURN_VALUE'], None)]

    code += tail

    co = types.CodeType(
        argcount,
        len(varnames),
        stacksize,
        func.func_code.co_flags & ~CO_GENERATOR,
        pyasm(code),
        consts,
        func.func_code.co_names,
        varnames,
        func.func_code.co_filename,
        func.func_code.co_name,
        func.func_code.co_firstlineno,
        func.func_code.co_lnotab,
        func.func_code.co_freevars,
        cellvars
        )

    argdefs = func.func_defaults or ()
    # Initialize un-initialized "local vars" to None
    argdefs = (None,) * (argcount - len(argdefs)) + argdefs

    func = types.FunctionType(co,
                              func.func_globals,
                              func.func_name,
                              argdefs,
                              func.func_closure)

    st = (init,)
    # Now we can do the actual fixed-point iteration
    for _ in xrange(max_iters):
        st_ = func(*st)
        stop, st_ = st_[0], st_[1:]
        if stop or st_[0] == st[0]:
            return st_[0]
        st = st_
    raise DivergentError

def fix(*args, **kwargs):
    func = None
    init = None
    miters = 1000

    if len(args) > 1:
        raise TypeError('fix() takes at most 1 positional argument (%d given)' \
                        % len(args))

    if args:
        if isinstance(args[0], (types.FunctionType, types.GeneratorType)):
            func = args[0]
        else:
            init = args[0]

    func = kwargs.pop('func', func)
    init = kwargs.pop('init', init)
    miters = kwargs.pop('max_iterations', miters)

    if kwargs:
        raise TypeError('fix() got an unexpected keyword argument \'%s\'' \
                        % kwargs.keys()[0])

    if func == None:
        def deco(func):
            return fix_(init, func, miters)
        return deco
    else:
        return fix_(init, func, miters)
