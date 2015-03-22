import codecs
import re
import sys
import textwrap


from instruction import Instruction
from disassemble import Disassembler


class Memory(bytearray):
    """Byte-addressable memory of length 65536.

    labels  - a list of (address, label name)
    strings - a list of (address, text)
    """

    _unicode_escape = codecs.getdecoder('unicode_escape')

    @staticmethod
    def _file_reader(f):
        for line in f:
            line = line.strip()
            if line != '':
                yield line

    def __init__(self):
        super().__init__(65536)
        self._write_addr = 0
        self.labels, self.strings = [], []

    def load(self, level):
        """
        Given the name of a (level), reads level+'.lst' and level+'.hex'
        to fill memory and store the addresses of labels and strings.
        """
        with open(level+'.lst') as f:
            self._load_lst(f)
        with open(level+'.hex') as f:
            self._load_hex(f)

    def _load_lst(self, f):
        hexword = re.compile('^[0-9a-f][0-9a-f][0-9a-f][0-9a-f]$')
        sblock = 0

        for line in self._file_reader(f):
            line = line.split('%%')[0]
            if line == '...' or line == '':
                continue
            first, rest = line.split(maxsplit=1)
            addr = self._write_addr = int(first[:4], 16)

            if rest.startswith('<'):
                self.labels.append((addr, rest[1:-1]))
            elif rest.startswith('.'):
                assert rest == '.strings:', 'unknown directive'
                self.labels.append((addr, '.strings' + str(sblock)))
                sblock += 1
            elif rest.startswith('"'):
                assert self.labels[-1][1].startswith('.strings'), \
                    'unexpected string'
                text = rest[1:-1]
                etext = self._unicode_escape(text)[0]
                for c in etext:
                    self._write_byte(ord(c))
                self._write_byte(0)
                self.strings.append((addr, text))
            else:
                for part in rest.split():
                    if not re.match(hexword, part):
                        break
                    self._write_word(int(part, 16))

        self.labels.append((self._write_addr, '.end'))

    def _load_hex(self, f):
        for line in self._file_reader(f):
            first, *rest = line.split()[:9]
            if rest[0] == '*':
                continue

            self._write_addr = int(first[:4], 16)
            for part in rest:
                self._write_word(int(part, 16))

    def _write_word(self, val):
        addr = self._write_addr
        self[addr] = val >> 8
        self[(addr + 1) & 0xffff] = val & 0xff
        self._write_addr = (addr + 2) & 0xffff

    def _write_byte(self, val):
        self[self._write_addr] = val
        self._write_addr = (self._write_addr + 1) & 0xffff

    def _read_word(self, addr):
        return (self[addr] << 8) | self[(addr + 1) & 0xffff]

    def dump(self, file=None):
        """Writes a hex dump to (file) (default sys.stdout)."""
        if file is None:
            file = sys.stdout
        starred = False

        for base_addr in range(0, 0x10000, 0x10):
            c1 = "%04x:" % base_addr
            for addr in range(base_addr, base_addr+0x10):
                if self[addr] != 0:
                    break
            else:
                if not starred:
                    print("%s   *" % c1, file=file)
                    starred = True
                continue

            starred = False
            mc = self[base_addr:base_addr+0x10]
            c2 = ''.join(map(lambda x: "%02x" % x, mc))
            c2 = ' '.join(textwrap.wrap(c2, 4))
            chars = (map(lambda x: chr(x) if x >= 32 and x < 127 else '.', mc))
            c3 = ''.join(chars)
            print("%s   %s   %s" % (c1, c2, c3), file=file)

    def listing(self, file=None):
        """Writes a listing to (file) (default sys.stdout)."""
        if file is None:
            file = sys.stdout
        dasm = self._dasm = Disassembler(self.labels, self.strings)
        for idx, (base, label) in enumerate(self.labels):
            if label == '.end':
                break
            if label.startswith('.strings'):
                nextbase = self.labels[idx+1][0]
                print("%04x .strings:" % base, file=file)
                for addr, text in self.strings:
                    if addr >= base and addr < nextbase:
                        print('%04x: "%s"' % (addr, text), file=file)
                continue
            print("%04x <%s>" % (base, label), file=file)
            while base < self.labels[idx+1][0]:
                if self._read_word(base) == 0:
                    base += 2
                    continue
                inst = Instruction(self, base)
                raw = ''.join(map(lambda x: "%02x" % x, self[base:inst.pc]))
                raw = ' '.join(textwrap.wrap(raw, 4))
                mnemonic, ops = dasm.disassemble(inst)
                ops = ', '.join(ops)
                line = "%04x:  %-14s %-9s %s" % (base, raw, mnemonic, ops)
                print(line.strip(), file=file)
                base = inst.pc
