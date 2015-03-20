from cpu import Cpu, CpuMeta, ExecError
from memory import Memory
from disassemble import Disassembler


class Monitor(metaclass=CpuMeta):
    def __init__(self, level):
        self._level = level
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
        self._brk = set()
        self.E()

    def B(self, target):
        if isinstance(target, str):
            target = self._d.find_label(target)
            if target is None:
                print("ERROR: unknown label")
                return
        if isinstance(target, int):
            if target > 0xffff:
                print("ERROR: address too large")
                return
        if target in self._brk:
            self._brk.remove(target)
            print("clear breakpoint %04x" % target)
        else:
            self._brk.add(target)
            print("set breakpoint %04x" % target)

    def C(self):
        try:
            c = self._cpu
            c.exec()
            inst = c.next_inst()
            while inst.startpc not in self._brk:
                c.exec_inst(inst)
                inst = c.next_inst()
        except ExecError as e:
            print(str(e))

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
        print('%04x: %-5s %s' %
              (inst.startpc, mnem, ', '.join(ops)))

    def I(self, ibytes):
        try:
            c = self._cpu
            if ibytes.startswith('0x'):
                ibytes = bytes.fromhex(ibytes[2:])
            else:
                ibytes = bytes(ibytes, 'ascii')
            c.send_input(ibytes)
        except ExecError as e:
            print(str(e))

    def S(self):
        try:
            c = self._cpu
            c.exec()
            self.E()
        except ExecError as e:
            print(str(e))
