from bisect import bisect

from instruction import AddrMode as AM
from instruction import *


class Disassembler:
    """Disassembles instructions.

    If provided, (labels) is a list of tuples (address, label name).
    If provided, (strings) is a list of tuples (address, text).
    """
    _reg_name = ['pc', 'sp', 'sr',  'cg',  'r4',  'r5',  'r6',  'r7',
                 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

    _mnemonic = [
        ['rrc',  'swpb', 'rra',  'sxt',  'push', 'call', 'reti', 'br'],
        ['clr',  'adc',  'sbc',  'tst',  'inc',  'dec',  'incd', 'decd', 'pop'],
        [None,   None,   None,   None,   'mov',  'add',  'addc', 'subc',
         'sub',  'cmp',  'dadd', 'bit',  'bic',  'bis',  'xor',  'and'],
        ['jnz',  'jz',   'jnc',  'jc',   'jn',   'jge',  'jl',   'jmp'],
        ['clrc', 'clrz', 'clrn', 'setc', 'setz', 'setn', 'nop',  'ret'],
    ]

    @staticmethod
    def _complement(val):
        if (val & 0x8000) == 0:
            return val
        return val - 0x10000

    def __init__(self, labels=None, strings=None):
        if labels is not None and len(labels) > 0:
            self._lidx, self._lname = [list(x) for x in zip(*labels)]
        else:
            self._lidx, self._lname = [0], ['.end']
        if strings is not None and len(strings) > 0:
            self._sidx, self._stext = [list(x) for x in zip(*strings)]
        else:
            self._sidx = []

    def find_label(self, name):
        if name not in self._lname:
            return None
        return self._lidx[self._lname.index(name)]

    def disassemble(self, inst):
        """
        Returns a tuple (mnemonic, [formatted operands])
        for a given instruction (inst)
        """
        if not inst.valid:
            return '.word', ["#%#04x" % inst.mv[0][1]]

        if inst.format == Format.DUAL:
            opcode, optype, width = self._check_emulation(inst)
        else:
            opcode, width = inst.opcode, inst.width
            if inst.format == Format.JUMP:
                optype = OpType.JUMP
            elif inst.format == Format.SINGLE:
                optype = OpType.SRC
            else:
                assert False, 'invalid instruction format'

        mnemonic = self._mnemonic[optype][opcode]
        suffix = '' if width.octets == 2 else '.b'
        return (mnemonic + suffix,
                self._get_ops(opcode, optype, width, inst.mv))

    def _get_ops(self, opcode, optype, width, mv):
        if optype == OpType.NONE:
            return []
        elif optype == OpType.SRC or optype == OpType.JUMP:
            return [self._op_text(opcode, optype, width, mv[0])]
        elif optype == OpType.SRC_DST:
            return [self._op_text(opcode, optype, width, mv[0]),
                    self._op_text(opcode, optype, width, mv[1])]
        elif optype == OpType.DST:
            return [self._op_text(opcode, optype, width, mv[1])]
        else:
            assert False, 'invalid optype'

    def _op_text(self, opcode, optype, width, mv):
        m, v = mv

        if optype == OpType.JUMP:
            return "#%#06x%s" % (v, self._label(v, exact=False))
        elif m == AM.CONSTANT:
            return "#%#x" % self._complement(v)
        elif m == AM.REGISTER:
            return self._reg_name[v]
        elif m == AM.INDEXED:
            val, reg = v
            return "%#x(%s)" % (self._complement(val), self._reg_name[reg])
        elif m == AM.ABSOLUTE:
                return "&%#06x" % v
        elif m == AM.INDIRECT:
            return "@%s" % self._reg_name[v]
        elif m == AM.IMMEDIATE:
            push = optype == OpType.SRC and opcode == Op.PUSH
            mov = optype == OpType.SRC_DST and opcode == Op.MOV
            call_or_br = optype == OpType.SRC and (opcode == Op.CALL
                                                or opcode == EmOp.BR)
            if (push or mov) and v in self._sidx:
                text = '"%s"' % self._stext[self._sidx.index(v)]
                return "#%#x %s" % (v, text)
            elif v != 0x10 and call_or_br:
                return "#%#x%s" % (v, self._label(v, exact=True))
            else:
                return "#%#x" % (v & width.max)
        elif m == AM.AUTOINC:
            return "@%s+" % self._reg_name[v]
        else:
            assert False, 'unknown address mode'

    def _label(self, target, exact):
        lidx, lname = self._lidx, self._lname
        idx = bisect(lidx, target) - 1
        base = lidx[idx]

        if lname[idx] == '.end' or lname[idx] == '.strings':
            return ''
        if exact and base != target:
            return ''

        if exact:
            return " <%s>" % lname[idx]
        else:
            return " <%s+%#x>" % (lname[idx], target - base)

    def _check_emulation(self, inst):
        opcode, (mv_src, mv_dst) = inst.opcode, inst.mv
        if mv_src[0] == AM.CONSTANT or mv_src[0] == AM.IMMEDIATE:
            src_const = mv_src[1]
        else:
            src_const = None

        if opcode == Op.MOV:
            to_pc = mv_dst == (AM.REGISTER, Reg.PC)
            from_sp = mv_src == (AM.AUTOINC, Reg.SP)
            if to_pc and from_sp:
                return EmOp.RET, OpType.NONE, Width.Word
            elif from_sp:
                return EmOp.POP, OpType.DST, inst.width
            elif to_pc:
                return EmOp.BR, OpType.SRC, Width.Word
            elif src_const == 0:
                if mv_dst == (AM.REGISTER, Reg.CG2):
                    return EmOp.NOP, OpType.NONE, Width.Word
                else:
                    return EmOp.CLR, OpType.DST, inst.width

        if mv_dst == (AM.REGISTER, Reg.SR):
            if opcode == Op.BIC:
                if src_const == 1:
                    return EmOp.CLRC, OpType.NONE, Width.Word
                elif src_const == 2:
                    return EmOp.CLRZ, OpType.NONE, Width.Word
                elif src_const == 4:
                    return EmOp.CLRN, OpType.NONE, Width.Word
            if opcode == Op.BIS:
                if src_const == 1:
                    return EmOp.SETC, OpType.NONE, Width.Word
                elif src_const == 2:
                    return EmOp.SETZ, OpType.NONE, Width.Word
                elif src_const == 4:
                    return EmOp.SETN, OpType.NONE, Width.Word

        if src_const == 0:
            if opcode == Op.ADDC:
                return EmOp.ADC, OpType.DST, inst.width
            elif opcode == Op.SUBC:
                return EmOp.SBC, OpType.DST, inst.width
            elif opcode == Op.CMP:
                return EmOp.TST, OpType.DST, inst.width
        elif src_const == 1:
            if opcode == Op.ADD:
                return EmOp.INC, OpType.DST, inst.width
            if opcode == Op.SUB:
                return EmOp.DEC, OpType.DST, inst.width
        elif src_const == 2:
            if opcode == Op.ADD:
                return EmOp.INCD, OpType.DST, inst.width
            if opcode == Op.SUB:
                return EmOp.DECD, OpType.DST, inst.width

        # Otherwise, the dual instruction has no emulation
        return opcode, OpType.SRC_DST, inst.width


class OpType:
    SRC     = 0
    DST     = 1
    SRC_DST = 2
    JUMP    = 3
    NONE    = 4


class EmOp:
    # Src
    BR   = 7
    # Dst
    CLR  = 0
    ADC  = 1
    SBC  = 2
    TST  = 3
    INC  = 4
    DEC  = 5
    INCD = 6
    DECD = 7
    POP  = 8
    # None
    CLRC = 0
    CLRZ = 1
    CLRN = 2
    SETC = 3
    SETZ = 4
    SETN = 5
    NOP  = 6
    RET  = 7
