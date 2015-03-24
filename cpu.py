from array import array
import random

from instruction import *
from instruction import AddrMode as AM


class CpuMeta(type):
    """Adds get/set properties for a cpu's registers."""
    def __init__(cls, name, bases, attrs):
        type.__init__(cls, name, bases, attrs)
        for i, n in enumerate(
                ['pc', 'sp', 'sr',  'cg',  'r4',  'r5',  'r6',  'r7',
                 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']):
            rget = lambda self, i=i: cls._getr(self, i)
            rset = lambda self, val, i=i: cls._setr(self, i, val)
            setattr(cls, n, property(rget, rset))


class Cpu(metaclass=CpuMeta):
    def __init__(self, mem):
        random.seed()
        self._mem = mem
        self._r = array('H', [0] * 16)
        self._r[Reg.PC] = self._read_data(0xfffe)
        self._pagetable = [Prot.NONE] * 256
        self._dep = False

        self._output = TestOutput()
        self._wait_input = None

        self._single = [self.RRC,  self.SWPB, self.RRA, self.SXT,
                        self.PUSH, self.CALL, self.RETI]

        self._jump = [self.JNZ, self.JZ,  self.JNC, self.JC,
                      self.JN,  self.JGE, self.JL,  self.JMP]

        self._dual = [None,     None,     None,      None,
                      self.MOV, self.ADD, self.ADDC, self.SUBC,
                      self.SUB, self.CMP, self.DADD, self.BIT,
                      self.BIC, self.BIS, self.XOR,  self.AND]

    def _getr(self, reg):
        return self._r[reg]

    def _setr(self, reg, val):
        self._r[reg] = val & 0xffff

    def next_inst(self):
        return Instruction(self._mem, self._r[Reg.PC])

    def exec(self):
        self.exec_inst(self.next_inst())

    def exec_inst(self, inst):
        if self.flag(Flag.CPUOFF):
            raise ExecError('cpu is halted')
        if self._wait_input is not None:
            raise ExecError('waiting for input')
        try:
            if not inst.valid:
                raise ExecError('illegal instruction')
            if (self._r[Reg.PC] & 0x1) != 0:
                raise ExecError('PC unaligned')
            self._r[Reg.PC] = inst.pc
            if self._pagetable[inst.pc >> 8] == Prot.NOEXEC and self._dep:
                raise ExecError('PC in non-executable page')
            if inst.format == Format.SINGLE:
                self._exec_single(inst)
            elif inst.format == Format.JUMP:
                self._exec_jump(inst)
            elif inst.format == Format.DUAL:
                self._exec_dual(inst)
            else:
                assert False, 'invalid instruction format'
        except ExecError as e:
            self.set_flag(Flag.CPUOFF, True)
            raise

    def flag(self, mask):
        return (self._r[Reg.SR] & mask) != 0

    def set_flag(self, mask, val):
        if val:
            self._r[Reg.SR] |= mask
        else:
            self._r[Reg.SR] &= (~mask & 0xffff)

    def send_input(self, ibytes):
        if self._wait_input is None:
            raise ExecError('not ready for input')
        self._wait_input.enter(self, ibytes)
        self._wait_input = None

    def _read_data(self, addr, width=Width.Word):
        if width.octets == 2 and (addr & 0x1) != 0:
            raise ExecError('load address unaligned')
        val = self._mem[addr & 0xffff]
        if width.octets == 2:
            val |= (self._mem[(addr + 1) & 0xffff] << 8)
        return val

    def _resolve_data(self, inst, n):
        mode, val = inst.mv[n]
        if mode == AM.CONSTANT or mode == AM.IMMEDIATE:
            return None, val & inst.width.max
        elif mode == AM.REGISTER:
            # Always return the full word, even in byte mode,
            # since opcodes that set the carry flag as (result < orig_dst)
            # compare the final value with the full 16-bit initial value,
            # even in byte mode.
            return val, self._r[val]
        elif mode == AM.ABSOLUTE:
            if n == 0 and (val & 0x1) != 0:
                raise ExecError('load address unaligned')
            return val, self._read_data(val, inst.width)
        elif mode == AM.INDEXED:
            offset, reg = val
            addr = (self._r[reg] + offset)
            return addr, self._read_data(addr, inst.width)
        elif mode == AM.INDIRECT:
            addr = self._r[val]
            return addr, self._read_data(addr, inst.width)
        elif mode == AM.AUTOINC:
            addr = self._r[val]
            self._setr(val, self._r[val] + inst.width.octets)
            return addr, self._read_data(addr, inst.width)
        else:
            assert False, 'invalid address mode'

    def _write_data(self, addr, data, width):
        if width.octets == 2 and (addr & 0x1) != 0:
            raise ExecError('store address unaligned')
        if self._pagetable[(addr & 0xffff) >> 8] == Prot.NOWRITE and self._dep:
            raise ExecError('write to non-writable page')
        self._mem[addr & 0xffff] = data & 0xff
        if width.octets == 2:
            self._mem[(addr + 1) & 0xffff] = data >> 8

    def _writeback(self, inst, n, addr, data):
        mode, val = inst.mv[n]
        if mode == AM.CONSTANT or mode == AM.IMMEDIATE:
            raise ExecError('invalid address mode for write operation')
        if mode == AM.REGISTER:
            self._r[addr] = data & inst.width.max
        else:
            self._write_data(addr, data, inst.width)

    def _exec_single(self, inst):
        addr, data = self._resolve_data(inst, 0)
        result = self._single[inst.opcode](data, inst.width)
        if inst.opcode < Op.PUSH:
            self._writeback(inst, 0, addr, result)

    def _exec_jump(self, inst):
        cond = inst.opcode
        target = inst.mv[0][1]
        if self._jump[cond]():
            self._r[Reg.PC] = target

    def _exec_dual(self, inst):
        _, d1 = self._resolve_data(inst, 0)
        addr, d2 = self._resolve_data(inst, 1)
        result = self._dual[inst.opcode](d1, d2, inst.width)
        if inst.opcode != Op.CMP and inst.opcode != Op.BIT:
            self._writeback(inst, 1, addr, result)

        if inst.startpc == 0x0010 \
           and self._read_data(0x0010) == 0x4130:
            self._gate()

    def _gate(self):
        interrupt = self._r[Reg.SR] >> 8
        arg = self._r[Reg.SP] + 6
        if interrupt == 0x80:
            self._output.write(chr(self._read_data(arg)))
        elif interrupt == 0x82:
            self._wait_input = TestInput(self._read_data(arg),
                                         self._read_data(arg + 2))
        elif interrupt == 0x90:
            self._dep = True
        elif interrupt == 0x91:
            self._pagetable[self._read_data(arg)] = self._read_data(arg + 2)
        elif interrupt == 0xa0:
            self._r[15] = random.randint(0, 0xffff)
        elif interrupt == 0xff:
            self.set_flag(Flag.CPUOFF, True)
            raise DoorUnlocked()

    def RRC(self, v1, width):
        self._r[Reg.SR] &= 0xff
        msb = width.neg if self.flag(Flag.C) else 0
        self.set_flag(Flag.C, (v1 & 0x1) != 0)
        result = ((v1 & width.max) >> 1) | msb
        # RRC sets, but never clears, the N flag
        if msb != 0:
            self.set_flag(Flag.N, True)
        self.set_flag(Flag.Z, result == 0)
        return result

    def SWPB(self, v1, width):
        return (v1 >> 8) | (v1 << 8)

    def RRA(self, v1, width):
        self._r[Reg.SR] &= 0xff
        msb = width.neg & v1
        # RRA sets, but never clears, the C flag
        if (v1 & 0x1) != 0:
            self.set_flag(Flag.C, True)
        result = ((v1 & width.max) >> 1) | msb
        self.set_flag(Flag.N, msb != 0)
        self.set_flag(Flag.Z, result == 0)
        return result

    def SXT(self, v1, width):
        self._r[Reg.SR] &= 0xff
        if (v1 & 0x80) != 0:
            result = v1 | 0xff00
            # SXT sets, but never clears, the N flag
            self.set_flag(Flag.N, True)
        else:
            result = v1 & 0xff
        self.set_flag(Flag.Z, result == 0)
        self.set_flag(Flag.C, result != 0)
        return result

    def PUSH(self, v1, width):
        self._setr(Reg.SP, self._r[Reg.SP] - 2)
        self._write_data(self._r[Reg.SP], v1, width)

    def CALL(self, v1, width):
        self.PUSH(self._r[Reg.PC], Width.Word)
        self._r[Reg.PC] = v1
        return

    def RETI(self, v1, width):
        return

    def JNZ(self):
        return not self.flag(Flag.Z)

    def JZ(self):
        return self.flag(Flag.Z)

    def JNC(self):
        return not self.flag(Flag.C)

    def JC(self):
        return self.flag(Flag.C)

    def JN(self):
        return self.flag(Flag.N)

    def JGE(self):
        return not self.JL()

    def JL(self):
        return ((self.flag(Flag.N) or self.flag(Flag.V))
                and not (self.flag(Flag.N) and self.flag(Flag.V)))

    def JMP(self):
        return True

    def MOV(self, v1, v2, width):
        return v1

    def ADD(self, v1, v2, width):
        result = (v1 + v2) & width.max
        self._r[Reg.SR] &= 0xff
        self.set_flag(Flag.N, (result & 0x8000) != 0)
        self.set_flag(Flag.Z, result == 0)
        self.set_flag(Flag.C, result < v2)
        return result

    def ADDC(self, v1, v2, width):
        C = self.flag(Flag.C)
        # Yes, the final carry flag is set based on carryless addition,
        # even though this opcode is add with carry.
        result = (v1 + v2) & width.max
        self._r[Reg.SR] &= 0xff
        self.set_flag(Flag.C, result < v2)
        if C:
            result = (result + 1) & width.max
        self.set_flag(Flag.N, (result & 0x8000) != 0)
        self.set_flag(Flag.Z, result == 0)
        return result

    def SUBC(self, v1, v2, width):
        return self.ADDC(-(v1 - (width.max + 1)), v2, width)

    def SUB(self, v1, v2, width):
        v2 = v2 & width.max
        result = self.ADD(-(v1 - (width.max + 1)), v2, width)
        if v1 == 0:
            self.set_flag(Flag.C, True)
        return result

    def CMP(self, v1, v2, width):
        self.SUB(v1, v2, width)

    def DADD(self, v1, v2, width):
        c = 1 if self.flag(Flag.C) else 0
        result = 0

        i = 0
        while i < width.nibbles:
            a = (v1 >> (i * 4)) & 0xf
            b = (v2 >> (i * 4)) & 0xf
            temp = a + b + c
            n = (temp & 0x8) != 0
            if temp >= 10:
                temp -= 10
                c = 1
            else:
                c = 0
            result |= ((temp & 0xf) << i)
            i += 1

        self._r[Reg.SR] &= 0xff
        self.set_flag(Flag.N, n)
        self.set_flag(Flag.Z, result == 0)
        self.set_flag(Flag.C, c != 0)
        return result

    def BIT(self, v1, v2, width):
        self.AND(v1, v2, width)

    def BIC(self, v1, v2, width):
        return ((~v1 & 0xffff) & v2) & width.max

    def BIS(self, v1, v2, width):
        return (v1 | v2) & width.max

    def XOR(self, v1, v2, width):
        result = (v1 ^ v2) & width.max
        self._r[Reg.SR] &= 0xff
        self.set_flag(Flag.N, (result & width.neg) != 0)
        self.set_flag(Flag.Z, result == 0)
        self.set_flag(Flag.C, result != 0)
        return result

    def AND(self, v1, v2, width):
        result = (v1 & v2) & width.max
        self._r[Reg.SR] &= 0xff
        self.set_flag(Flag.N, (result & width.neg) != 0)
        self.set_flag(Flag.Z, result == 0)
        self.set_flag(Flag.C, result != 0)
        return result


class TestInput:
    def __init__(self, ptr, length):
        self._ptr = ptr
        self._length = length

    def enter(self, c, ibytes):
        for i in range(min(self._length, len(ibytes))):
            c._write_data(self._ptr, ibytes[i], Width.Byte)
            self._ptr += 1
        c._write_data(self._ptr, 0, Width.Byte)


class TestOutput:
    def __init__(self):
        self.text = ''
    def write(self, text):
        if text != '\n':
            self.text += text
        else:
            print("OUTPUT:", self.text)
            self.text = ''


class Flag:
    C      = 0b000000001
    Z      = 0b000000010
    N      = 0b000000100
    CPUOFF = 0b000010000
    V      = 0b100000000


class Prot:
    NOWRITE = 0
    NOEXEC  = 1
    NONE    = 2


class ExecError(Exception): pass
class DoorUnlocked(Exception): pass
