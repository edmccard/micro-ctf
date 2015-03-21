from enum import Enum


class DecodeError(Exception): pass


class Width(Enum):
    """Information that varies on byte/word data access.

    octets  - size in octets
    nibbles - size in nibbles
    max     - maximum value
    neg     - bitmask for the sign bit
    """

    Word = (2, 4, 0xffff, 0x8000)
    Byte = (1, 2, 0xff, 0x80)

    def __init__(self, octets, nibbles, max, neg):
        self.octets = octets
        self.nibbles = nibbles
        self.max = max
        self.neg = neg

class Instruction:
    """A decoded instruction.

    Instructions are decoded from a sequence of bytes (mem) at a particular
    position (pc).

    startpc - pc before decoding
    pc      - pc after decoding
    valid   - was mem[pc] a legal instruction?
    format  - Format.SINGLE, Format.JUMP, Format.DUAL
    opcode  - the format-specific opcode number
    width   - Width.Word or Width.Byte
    mv[]    - (address mode, value) for src (mv[0]) and dst (mv[1]) operands;
              see AddrMode for the various meanings of value
    """
    __slots__ = ['pc', 'startpc', 'valid', 'format',
                 'opcode', 'width', 'mv']

    _widths = [Width.Word, Width.Byte]

    def __init__(self, mem, pc):
        self.startpc = self.pc = pc
        word = self._read_pc(mem)
        self.valid = False

        try:
            if word < 0x2000:
                self._decode_single(mem, word)
            elif word < 0x4000:
                self._decode_jump(word)
            else:
                self._decode_dual(mem, word)
        except DecodeError:
            self.pc = pc
            self.mv = [(None, word)]
            return

        self.valid = True

    def _decode_single(self, mem, word):
        s_reg       = word        & 0b1111
        a_s         = (word >> 4) & 0b11
        bw          = (word >> 6) & 0b1
        self.opcode = (word >> 7) & 0b111

        if self.opcode == 0b111:
            raise DecodeError('invalid single opcode')

        if (self.opcode & 0x1) != 0 or self.opcode == Op.RETI:
            bw = 0
        self.width = self._widths[bw]
        self.format = Format.SINGLE
        self.mv = [self._addr_mode(s_reg, a_s, mem)]

    def _decode_jump(self, word):
        offset        = word         & 0b1111111111
        self.opcode   = (word >> 10) & 0b111

        if (offset & 0b1000000000) != 0:
            offset = offset - 0x400

        self.width = Width.Word
        self.format = Format.JUMP
        self.mv = [(offset, (self.pc + offset * 2) % 0xffff)]

    def _decode_dual(self, mem, word):
        d_reg       = word        & 0b1111
        a_s         = (word >> 4) & 0b11
        bw          = (word >> 6) & 0b1
        a_d         = (word >> 7) & 0b1
        s_reg       = (word >> 8) & 0b1111
        self.opcode = word >> 12

        self.width = self._widths[bw]
        self.format = Format.DUAL
        self.mv = [self._addr_mode(s_reg, a_s, mem),
                   self._addr_mode(d_reg, a_d, mem, dest=True)]

    def _addr_mode(self, reg, a, mem, dest=False):
        if a == 0:
            if reg == Reg.CG2 and not dest:
                return AddrMode.CONSTANT, 0x0
            else:
                return AddrMode.REGISTER, reg
        elif a == 1:
            if reg == Reg.CG1:
                addr = self._read_pc(mem)
                return AddrMode.ABSOLUTE, addr
            elif reg == Reg.CG2 and not dest:
                return AddrMode.CONSTANT, 0x1
            else:
                offset = self._read_pc(mem)
                return AddrMode.INDEXED, (offset, reg)
        elif a == 2:
            if reg == Reg.CG1:
                return AddrMode.CONSTANT, 0x4
            elif reg == Reg.CG2:
                return AddrMode.CONSTANT, 0x2
            else:
                return AddrMode.INDIRECT, reg
        elif a == 3:
            if reg == Reg.PC:
                val = self._read_pc(mem)
                return AddrMode.IMMEDIATE, val
            elif reg == Reg.CG1:
                return AddrMode.CONSTANT, 0x8
            elif reg == Reg.CG2:
                return AddrMode.CONSTANT, 0xffff
            else:
                return AddrMode.AUTOINC, reg
        else:
            assert False, 'bad address mode bits'

    def _read_pc(self, mem):
        m1, m2 = self.pc, (self.pc + 1) & 0xffff
        self.pc = (self.pc + 2) & 0xffff
        return mem[m1] | (mem[m2] << 8)


class Format:
    SINGLE = 0
    JUMP = 1
    DUAL = 2


class Reg:
    PC  = 0
    SP  = 1
    SR  = 2
    CG1 = 2
    CG2 = 3


class AddrMode:
    """Address modes.

    Mode       Instruction.mv
    -----------------------------------------------------
    CONSTANT   Literal constant 0, 1, 2, 4, 8, or -1
    REGISTER   Register number 0-15
    ABSOLUTE   Operand address 0-0xffff
    INDEXED    Tuple of: operand address, register number
    INDIRECT   Register number
    IMMEDIATE  Operand constant
    AUTOINC    Register number

    """
    CONSTANT  = 0
    REGISTER  = 1
    ABSOLUTE  = 2
    INDEXED   = 3
    INDIRECT  = 4
    IMMEDIATE = 5
    AUTOINC   = 6


class Op:
    # Single
    RRC  = 0
    SWPB = 1
    RRA  = 2
    SXT  = 3
    PUSH = 4
    CALL = 5
    RETI = 6
    # Jump
    JNZ  = 0
    JZ   = 1
    JNC  = 2
    JC   = 3
    JN   = 4
    JGE  = 5
    JL   = 6
    JMP  = 7
    # Dual
    MOV  = 4
    ADD  = 5
    ADDC = 6
    SUBC = 7
    SUB  = 8
    CMP  = 9
    DADD = 10
    BIT  = 11
    BIC  = 12
    BIS  = 13
    XOR  = 14
    AND  = 15
