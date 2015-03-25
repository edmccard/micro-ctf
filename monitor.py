from operator import itemgetter
import os
import textwrap

from cpu import *
from disassemble import Disassembler
from memory import Memory


class Monitor(metaclass=CpuMeta):
    def __init__(self, level):
        self._level = level
        self._bps = {}
        self.reset()

    def _getr(self, reg):
        return self._cpu._r[reg]

    def _setr(self, reg, val):
        self._cpu._r[reg] = val & 0xffff

    def reset(self):
        self._mem = Memory()
        self._mem.load(self._level)
        self._cpu = Cpu(self._mem)
        self._d = Disassembler(self._mem.labels, self._mem.strings)
        self._unlocked = False
        self._cbrk = None
        self.E()

    def brk(self, target=False, *, silent=False):
        if target is None:
            self._bps = {}
            return
        elif not target:
            points = sorted(list(self._bps.values()))
            for (addr, label) in points:
                print("%04x  %s" % (addr, '' if label is None else label))
            return
        elif isinstance(target, str):
            addr = self._d.find_label(target)
            if target is None:
                print("ERROR: unknown label")
                return
        elif isinstance(target, int) and target < 0x10000:
            addr = target
            target = None
        else:
            print("cannot set breakpoint %s" % target)

        bps = self._bps
        if addr in bps:
            del bps[addr]
            if not silent:
                print("clear breakpoint %04x" % addr)
        else:
            bps[addr] = (addr, target)
            if not silent:
                print("set breakpoint %04x" % addr)

    def C(self, b=None):
        if b is not None:
            if b != self._cbrk:
                self.brk(b, silent=True)
            self._cbrk = b
        try:
            c = self._cpu
            c.exec()
            while c.pc not in self._bps:
                c.exec()
            self.E()
            if self._cbrk is not None:
                self.brk(self._cbrk, silent=True)
                self._cbrk = None
        except ExecError as e:
            print(str(e))
        except DoorUnlocked:
            self._unlocked = True
            print("DOOR UNLOCKED!")

    def D(self, line1, line2=None):
        if line2 is None:
            line2 = line1
        line1 &= 0xfff0
        line2 &= 0xfff0
        for line in range(line1, line2+0x10, 0x10):
            data = self._mem[line:line+0x10]
            asc = map(lambda x: chr(x) if x >= 32 and x < 127 else '.', data)
            asc = ''.join(asc)
            dump = ''.join(map(lambda x: "%02x" % x, data))
            dump = ' '.join(textwrap.wrap(dump, 4))
            print("%04x:   %s   %s" % (line, dump, asc))

    def E(self):
        c = self._cpu
        print()
        print(('pc  %04x  sp  %04x  sr  %04x  cg  %04x  ' +
               'r04 %04x  r05 %04x  r06 %04x  r07 %04x') %
              (c.pc, c.sp, c.sr, c.cg, c.r4, c.r5, c.r6, c.r7))
        print(('r08 %04x  r09 %04x  r10 %04x  r11 %04x  ' +
               'r12 %04x  r13 %04x  r14 %04x  r15 %04x') %
              (c.r8, c.r9, c.r10, c.r11, c.r12, c.r13, c.r14, c.r15))
        print('-' * 78)
        inst = c.next_inst()
        mnem, ops = self._d.disassemble(inst)
        print('%04x: %-6s %s' %
              (inst.startpc, mnem, ', '.join(ops)))

    def I(self, ibytes=None):
        try:
            c = self._cpu
            if ibytes is None:
                ibytes = b''
            if isinstance(ibytes, str):
                if ibytes.startswith('0x'):
                    ibytes = bytes.fromhex(ibytes[2:])
                else:
                    ibytes = bytes(ibytes, 'ascii')
            if not isinstance(ibytes, bytes):
                print("ERROR: input must be string or bytes")
                return
            c.send_input(ibytes)
        except ExecError as e:
            print(str(e))

    def N(self):
        c = self._cpu
        inst = c.next_inst()
        oldcbrk = self._cbrk
        oldbps = self._bps
        self.C(inst.pc)
        self._cbrk = oldcbrk
        self._bps = oldbps

    def S(self):
        try:
            c = self._cpu
            c.exec()
            self.E()
        except ExecError as e:
            print(str(e))
        except DoorUnlocked:
            self._unlocked = True
            print("DOOR UNLOCKED!")


def test(soldir):
    f = open(os.path.join(soldir, 'solutions.txt'))
    ok = True

    for line in f:
        level, sol = line.split()
        m = Monitor(os.path.join(soldir, level))
        try:
            m.C()
            for inp in sol.split(','):
                m.I(bytes.fromhex(inp))
                m.C()
            if not m._unlocked:
                ok = False
                print(level, "failed")
        except:
            print(level, " failed")
            ok = False

    f.close()
    return ok
