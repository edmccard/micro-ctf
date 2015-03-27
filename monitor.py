from operator import itemgetter
import os
import textwrap

from cpu import *
from disassemble import Disassembler
from memory import Memory


class Monitor(metaclass=CpuMeta):
    def __init__(self, level, *, seed=None):
        self._level = level
        self._bps = {}
        self._seed = seed
        self.reset()

    def _getr(self, reg):
        return self._cpu._r[reg]

    def _setr(self, reg, val):
        self._cpu._r[reg] = val & 0xffff

    def reset(self):
        self._mem = Memory()
        self._mem.load(self._level)
        self._cpu = Cpu(self._mem, seed=self._seed)
        self._d = Disassembler(self._mem.labels, self._mem.strings)
        self._unlocked = False
        self._cbrk = None
        self._tracefile = None
        self._tracing = False
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

    def trace(self, tracefile=None):
        if tracefile is None:
            if self._tracefile is None:
                print("please specify a trace file")
                return
            if self._tracing:
                self._tracing = False
                print("trace off")
            else:
                self._tracing = True
                print("trace on")
        else:
            if self._tracefile is None:
                self._tracing = True
                print("trace on")
            self._tracefile = tracefile

    def _getdis(self, inst):
        mnem, ops = self._d.disassemble(inst)
        return '%04x: %-6s %s' % (inst.startpc, mnem, ', '.join(ops))

    def _gettrace(self, inst):
        return self._getdis(inst)

    def _step(self):
        try:
            inst = self._cpu.next_inst()
            self._cpu.exec_inst(inst)
            if self._tracing:
                print(self._gettrace(inst), file=self._tracefile)
            return True
        except ExecError as e:
            print(str(e))
        except DoorUnlocked:
            self._unlocked = True
            print("DOOR UNLOCKED!")
        return False

    def C(self, b=None):
        if b is not None:
            if b != self._cbrk:
                self.brk(b, silent=True)
            self._cbrk = b
        if self._tracing:
            print(file=self._tracefile)
            print("CONTINUE", file=self._tracefile)
            print(file=self._tracefile)
        while True:
            if not self._step():
                break
            if self._cpu.pc in self._bps:
                self.E()
                break
        if self._cbrk is not None:
            self.brk(self._cbrk, silent=True)
            self._cbrk = None

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
        print(self._getdis(inst))

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
        if self._step():
            self.E()


class MonitorX(Monitor):
    def reset(self):
        super().reset()
        self._cpu = CpuX(self._cpu._mem, seed=self._seed)

    def _gettrace(self, inst):
        mnem, ops = self._d.disassemble(inst)
        d1 = '%04x: %-6s %s' % (inst.startpc, mnem, ', '.join(ops))
        d2 = []
        if inst.format != Format.JUMP:
            try:
                for lv in inst.live[:-1]:
                    if len(lv) == 1:
                        lvstr = "%04x" % lv[0]
                    else:
                        lvstr = "[%04x]:%04x" % (lv[0], lv[1])
                    d2.append(lvstr)
                if inst.live[-1] is not None:
                    d2.append("%04x" % inst.live[-1])
            except AttributeError:
                print(inst.format)
        return d1 + ' -- ' + ' '.join(d2)


def test(soldir):
    f = open(os.path.join(soldir, 'solutions.txt'))
    ok = True
    fails = []

    for line in f:
        level, sol = line.split()
        print("testing", level)
        m = Monitor(os.path.join(soldir, level))
        try:
            m.C()
            for inp in sol.split(','):
                m.I(bytes.fromhex(inp))
                m.C()
            if not m._unlocked:
                ok = False
                fails.append(level)
                print(level, "failed")
        except:
            fails.append(level)
            print(level, " failed")
            ok = False

    if not ok:
        print("Failures:")
        for fail in fails:
            print(fail)

    f.close()
    return ok
