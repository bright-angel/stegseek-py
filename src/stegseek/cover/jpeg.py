"""JPEG DCT-coefficient access, compatible with libjpeg's ``jpeg_read_coefficients``.

Baseline (SOF0) and progressive (SOF2) files are decoded to the same
component-major / block-row / block-column / coefficient order that steghide
uses.  Writing produces a baseline JPEG from those coefficients (which is
exactly what steghide's ``jpeg_write_coefficients`` does).
"""

from __future__ import annotations

import struct

from ..errors import UnSupFileFormat
from .base import CoverFile, div_roundup

# jpeg_natural_order: zigzag index -> natural (row-major) coefficient index
ZIGZAG = (
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
)

# Standard JPEG Huffman tables (used when re-encoding a progressive input).
STD_DC_BITS = (0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0)
STD_DC_VALUES = tuple(range(12))
STD_AC_BITS = (0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7D)
STD_AC_VALUES = (
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61,
    0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52,
    0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25,
    0x26, 0x27, 0x28, 0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
    0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83,
    0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
    0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
    0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3,
    0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
    0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
)


def _round_up(value: int, multiple: int) -> int:
    return ((value + multiple - 1) // multiple) * multiple


class HuffTable:
    __slots__ = ("decode", "encode")

    def __init__(self, counts: tuple[int, ...], symbols: tuple[int, ...]):
        self.decode: dict[tuple[int, int], int] = {}
        self.encode: dict[int, tuple[int, int]] = {}
        code = 0
        k = 0
        for length in range(1, 17):
            for _ in range(counts[length - 1]):
                self.decode[(length, code)] = symbols[k]
                self.encode[symbols[k]] = (code, length)
                code += 1
                k += 1
            code <<= 1

    def symbol(self, reader: "BitReader") -> int:
        code = 0
        for length in range(1, 17):
            code = (code << 1) | reader.get_bit()
            found = self.decode.get((length, code))
            if found is not None:
                return found
        raise ValueError("bad Huffman code")


class BitReader:
    __slots__ = ("data", "pos", "buffer", "bits_left")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.buffer = 0
        self.bits_left = 0

    def get_bit(self) -> int:
        if self.bits_left == 0:
            if self.pos >= len(self.data):
                self.buffer = 0xFF  # libjpeg feeds 1-bits at end of a segment
            else:
                self.buffer = self.data[self.pos]
            self.pos += 1
            self.bits_left = 8
        self.bits_left -= 1
        return (self.buffer >> self.bits_left) & 1

    def get_bits(self, n: int) -> int:
        value = 0
        for _ in range(n):
            value = (value << 1) | self.get_bit()
        return value

    def receive_extend(self, n: int) -> int:
        if n == 0:
            return 0
        value = self.get_bits(n)
        if value < (1 << (n - 1)):
            value -= (1 << n) - 1
        return value


class BitWriter:
    __slots__ = ("out", "acc", "nbits")

    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.nbits = 0

    def put(self, code: int, length: int) -> None:
        for i in range(length - 1, -1, -1):
            self.acc = (self.acc << 1) | ((code >> i) & 1)
            self.nbits += 1
            if self.nbits == 8:
                byte = self.acc & 0xFF
                self.out.append(byte)
                if byte == 0xFF:
                    self.out.append(0x00)
                self.acc = 0
                self.nbits = 0

    def flush(self) -> bytes:
        if self.nbits:
            self.acc = (self.acc << (8 - self.nbits)) | ((1 << (8 - self.nbits)) - 1)
            byte = self.acc & 0xFF
            self.out.append(byte)
            if byte == 0xFF:
                self.out.append(0x00)
            self.acc = 0
            self.nbits = 0
        return bytes(self.out)


def _category(value: int) -> int:
    return abs(value).bit_length()


def _value_bits(value: int, category: int) -> int:
    return value if value >= 0 else value + (1 << category) - 1


class JpegFile(CoverFile):
    format_name = "jpeg"

    def __init__(self, path: str, raw: bytes):
        super().__init__(path, raw)
        self.samples_per_vertex = 3
        self.modulus = 2
        self.quant_tables: dict[int, list[int]] = {}
        self.dc_tables: dict[int, HuffTable] = {}
        self.ac_tables: dict[int, HuffTable] = {}
        self.components: list[dict] = []
        self.width = self.height = 0
        self.max_h = self.max_v = 1
        self.progressive = False
        self.restart_interval = 0
        self.app_segments: list[bytes] = []
        self.blocks: list[list[list[list[int]]]] = []
        self.block_w: list[int] = []
        self.block_h: list[int] = []
        self.pad_w: list[int] = []
        self.pad_h: list[int] = []
        self._parse()
        self._linearize()

    # ------------------------------------------------------------------ parsing
    def _parse(self) -> None:
        data = self.raw
        if len(data) < 4 or data[:2] != b"\xff\xd8":
            raise UnSupFileFormat('the file format of the file "%s" is not supported.' % self.name)
        pos = 2
        scans: list[dict] = []
        while pos < len(data) - 1:
            if data[pos] != 0xFF:
                raise UnSupFileFormat("invalid jpeg marker stream")
            marker = data[pos + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                pos += 2
                continue
            if marker == 0xD9:
                break
            if pos + 4 > len(data):
                break
            length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            payload = data[pos + 4:pos + 2 + length]
            head = pos
            pos += 2 + length

            if 0xE0 <= marker <= 0xEF or marker == 0xFE:
                self.app_segments.append(data[head:pos])
            elif marker == 0xDB:
                self._parse_dqt(payload)
            elif marker == 0xC4:
                self._parse_dht(payload)
            elif marker in (0xC0, 0xC1, 0xC2, 0xC3):
                self._parse_sof(marker, payload)
            elif marker == 0xDD:
                self.restart_interval = struct.unpack(">H", payload[:2])[0]
            elif marker == 0xDA:
                scan = self._parse_sos(payload)
                # Progressive files may redefine tables / DRI between scans.
                # Snapshot the state that is in effect for *this* scan.
                scan["dc_tables"] = dict(self.dc_tables)
                scan["ac_tables"] = dict(self.ac_tables)
                scan["quant_tables"] = {k: list(v) for k, v in self.quant_tables.items()}
                scan["restart_interval"] = self.restart_interval
                end = pos
                while end < len(data) - 1:
                    if data[end] == 0xFF and data[end + 1] not in (0x00, 0xFF) \
                            and not (0xD0 <= data[end + 1] <= 0xD7):
                        break
                    end += 1
                scan["entropy"] = data[pos:end]
                scans.append(scan)
                pos = end
        if not self.components:
            raise UnSupFileFormat("no JPEG frame header found")
        self._allocate_blocks()
        for scan in scans:
            self._decode_scan(scan)

    def _parse_dqt(self, payload: bytes) -> None:
        p = 0
        while p < len(payload):
            info = payload[p]
            p += 1
            precision = info >> 4
            table = []
            for _ in range(64):
                if precision:
                    table.append(struct.unpack(">H", payload[p:p + 2])[0])
                    p += 2
                else:
                    table.append(payload[p])
                    p += 1
            self.quant_tables[info & 15] = table

    def _parse_dht(self, payload: bytes) -> None:
        p = 0
        while p < len(payload):
            info = payload[p]
            p += 1
            counts = tuple(payload[p:p + 16])
            p += 16
            nsyms = sum(counts)
            symbols = tuple(payload[p:p + nsyms])
            p += nsyms
            table = HuffTable(counts, symbols)
            if info >> 4 == 0:
                self.dc_tables[info & 15] = table
            else:
                self.ac_tables[info & 15] = table

    def _parse_sof(self, marker: int, payload: bytes) -> None:
        self.progressive = marker == 0xC2
        self.height, self.width, ncomp = struct.unpack(">HHB", payload[1:6])
        self.components = []
        for i in range(ncomp):
            cid, samp, tq = payload[6 + 3 * i:9 + 3 * i]
            self.components.append({"id": cid, "h": samp >> 4, "v": samp & 15, "tq": tq,
                                    "index": i})
        self.max_h = max(c["h"] for c in self.components)
        self.max_v = max(c["v"] for c in self.components)

    def _parse_sos(self, payload: bytes) -> dict:
        ns = payload[0]
        comps = []
        by_id = {c["id"]: c["index"] for c in self.components}
        for i in range(ns):
            cid, tables = payload[1 + 2 * i:3 + 2 * i]
            comps.append({"index": by_id.get(cid, i), "dc": tables >> 4, "ac": tables & 15})
        ss, se, ahal = payload[1 + 2 * ns:4 + 2 * ns]
        return {"comps": comps, "ss": ss, "se": se, "ah": ahal >> 4, "al": ahal & 15}

    def _allocate_blocks(self) -> None:
        for comp in self.components:
            w = div_roundup(self.width * comp["h"], 8 * self.max_h)
            h = div_roundup(self.height * comp["v"], 8 * self.max_v)
            pw = _round_up(w, comp["h"])
            ph = _round_up(h, comp["v"])
            self.block_w.append(w)
            self.block_h.append(h)
            self.pad_w.append(pw)
            self.pad_h.append(ph)
            self.blocks.append([[[0] * 64 for _ in range(pw)] for _ in range(ph)])

    # ----------------------------------------------------------------- decoding
    @staticmethod
    def _split_entropy(data: bytes) -> list[bytes]:
        segments: list[bytearray] = []
        current = bytearray()
        i = 0
        while i < len(data):
            byte = data[i]
            if byte == 0xFF and i + 1 < len(data):
                nxt = data[i + 1]
                if nxt == 0x00:
                    current.append(0xFF)
                    i += 2
                    continue
                if 0xD0 <= nxt <= 0xD7:
                    segments.append(current)
                    current = bytearray()
                    i += 2
                    continue
                if nxt == 0xFF:
                    i += 1
                    continue
                break
            current.append(byte)
            i += 1
        segments.append(current)
        return [bytes(s) for s in segments]

    def _scan_mcus(self, scan: dict) -> list[list[tuple[int, int, int]]]:
        """List of MCUs; each MCU is a list of (component index, row, col).

        libjpeg pads the coefficient arrays to whole iMCU boundaries, but a scan
        still contains exactly ``width_in_blocks * height_in_blocks`` MCUs (the
        unpadded dimensions).  steghide likewise linearises only the unpadded
        blocks, so the padded blocks are never read.
        """
        comps = scan["comps"]
        if len(comps) > 1:
            mcu_rows = div_roundup(self.height, 8 * self.max_v)
            mcu_cols = div_roundup(self.width, 8 * self.max_h)
            result = []
            for r in range(mcu_rows):
                for c in range(mcu_cols):
                    mcu = []
                    for sc in comps:
                        ci = sc["index"]
                        comp = self.components[ci]
                        for y in range(comp["v"]):
                            for x in range(comp["h"]):
                                mcu.append((ci, r * comp["v"] + y, c * comp["h"] + x))
                    result.append(mcu)
            return result

        ci = comps[0]["index"]
        return [[(ci, row, col)] for row in range(self.block_h[ci])
                for col in range(self.block_w[ci])]

    @staticmethod
    def _ac_first(reader: "BitReader", table: "HuffTable", block: list[int],
                  ss: int, se: int, al: int) -> int:
        """Port of libjpeg's ``decode_mcu_AC_first`` (also used for baseline).

        Returns the number of remaining blocks covered by the EOB run.
        """
        k = ss
        while k <= se:
            symbol = table.symbol(reader)
            r, s = symbol >> 4, symbol & 15
            if s:
                k += r
                if k > se:
                    break
                block[ZIGZAG[k]] = reader.receive_extend(s) << al
            elif r == 15:  # ZRL: skip 16 zero coefficients
                k += 15
            else:  # EOBr
                eobrun = 1 << r
                if r:
                    eobrun += reader.get_bits(r)
                return eobrun - 1
            k += 1
        return 0

    @staticmethod
    def _ac_refine(reader: "BitReader", table: "HuffTable", block: list[int],
                   ss: int, se: int, p1: int, m1: int, eobrun: int) -> int:
        """Port of libjpeg's ``decode_mcu_AC_refine``."""
        k = ss
        if eobrun == 0:
            while k <= se:
                symbol = table.symbol(reader)
                r, s = symbol >> 4, symbol & 15
                if s:
                    s = p1 if reader.get_bit() else m1
                else:
                    if r != 15:  # EOBr
                        eobrun = 1 << r
                        if r:
                            eobrun += reader.get_bits(r)
                        break
                    # s == 0: ZRL, only correction bits follow
                while k <= se:
                    pos = ZIGZAG[k]
                    current = block[pos]
                    if current != 0:
                        if reader.get_bit() and (current & p1) == 0:
                            block[pos] = current + (p1 if current >= 0 else m1)
                    else:
                        r -= 1
                        if r < 0:
                            break
                    k += 1
                if s and k <= se:
                    block[ZIGZAG[k]] = s
                k += 1
        if eobrun > 0:
            while k <= se:
                pos = ZIGZAG[k]
                current = block[pos]
                if current != 0:
                    if reader.get_bit() and (current & p1) == 0:
                        block[pos] = current + (p1 if current >= 0 else m1)
                k += 1
            eobrun -= 1
        return eobrun

    def _decode_scan(self, scan: dict) -> None:
        segments = self._split_entropy(scan["entropy"])
        readers = [BitReader(seg) for seg in segments]
        dc_tables = scan["dc_tables"]
        ac_tables = scan["ac_tables"]
        comps_by_index = {sc["index"]: sc for sc in scan["comps"]}
        mcus = self._scan_mcus(scan)
        restart_interval = scan["restart_interval"]
        seg_idx = 0
        reader = readers[0]
        dc_pred = {sc["index"]: 0 for sc in scan["comps"]}
        eobrun = 0
        ss, se, ah, al = scan["ss"], scan["se"], scan["ah"], scan["al"]
        # A baseline scan carries DC *and* AC (1..63) for every block in the MCU.
        baseline = (not self.progressive) and ss == 0 and se == 63 and ah == 0 and al == 0
        dc_only = ss == 0 and se == 0
        p1 = 1 << al
        m1 = -1 << al

        for mcu_index, mcu in enumerate(mcus):
            if restart_interval and mcu_index and \
                    mcu_index % restart_interval == 0 and seg_idx + 1 < len(readers):
                seg_idx += 1
                reader = readers[seg_idx]
                dc_pred = {sc["index"]: 0 for sc in scan["comps"]}
                eobrun = 0

            if baseline:
                for ci, row, col in mcu:
                    sc = comps_by_index[ci]
                    block = self.blocks[ci][row][col]
                    size = dc_tables[sc["dc"]].symbol(reader)
                    dc_pred[ci] += reader.receive_extend(size)
                    block[0] = dc_pred[ci]
                    self._ac_first(reader, ac_tables[sc["ac"]], block, 1, 63, 0)
                continue

            if dc_only and ah == 0:  # progressive DC first
                for ci, row, col in mcu:
                    sc = comps_by_index[ci]
                    size = dc_tables[sc["dc"]].symbol(reader)
                    dc_pred[ci] += reader.receive_extend(size)
                    self.blocks[ci][row][col][0] = dc_pred[ci] << al
            elif dc_only:  # progressive DC refine
                for ci, row, col in mcu:
                    if reader.get_bit():
                        self.blocks[ci][row][col][0] |= p1
            elif ah == 0:  # progressive AC first
                ci, row, col = mcu[0]
                table = ac_tables[scan["comps"][0]["ac"]]
                block = self.blocks[ci][row][col]
                if eobrun > 0:
                    eobrun -= 1
                else:
                    eobrun = self._ac_first(reader, table, block, ss, se, al)
            else:  # progressive AC refine
                ci, row, col = mcu[0]
                table = ac_tables[scan["comps"][0]["ac"]]
                block = self.blocks[ci][row][col]
                eobrun = self._ac_refine(reader, table, block, ss, se, p1, m1, eobrun)

    def _linearize(self) -> None:
        linear: list[int] = []
        self.linear_block_map: list[tuple[int, int, int]] = []
        for ci in range(len(self.components)):
            for row in range(self.block_h[ci]):
                for col in range(self.block_w[ci]):
                    self.linear_block_map.append((ci, row, col))
                    linear.extend(self.blocks[ci][row][col])
        self.linear = linear
        self.stego_indices = [i for i, value in enumerate(linear) if value != 0]
        self._finalize_evalues([abs(linear[i]) % 2 for i in self.stego_indices])

    # ------------------------------------------------------------------- samples
    def set_embedded_value(self, pos: int, target: int) -> None:
        index = self.stego_indices[pos]
        value = self.linear[index]
        if abs(value) % 2 == target:
            return
        if value > 0:
            new_value = value + 1 if value < 32767 else value - 1
        else:
            new_value = value - 1 if value > -32768 else value + 1
        if new_value == 0 or abs(new_value) % 2 != target:
            new_value = -value if value != 0 else 1
        self.linear[index] = new_value
        self.evalues[pos] = target
        ci, row, col = self.linear_block_map[index // 64]
        self.blocks[ci][row][col][index % 64] = new_value

    # -------------------------------------------------------------------- writing
    def to_bytes(self) -> bytes:
        # Rebuild a baseline JPEG using the standard Huffman tables.
        out = bytearray(b"\xff\xd8")
        for seg in self.app_segments:
            out.extend(seg)

        dqt = bytearray()
        for tid, table in sorted(self.quant_tables.items()):
            precision = 1 if max(table, default=0) > 255 else 0
            dqt.append((precision << 4) | tid)
            if precision:
                for value in table:
                    dqt.extend(struct.pack(">H", value))
            else:
                dqt.extend(table)
        out.extend(b"\xff\xdb" + struct.pack(">H", len(dqt) + 2) + dqt)

        sof = bytearray()
        sof.append(8)
        sof.extend(struct.pack(">HH", self.height, self.width))
        sof.append(len(self.components))
        for comp in self.components:
            sof.extend(bytes((comp["id"], (comp["h"] << 4) | comp["v"], comp["tq"])))
        out.extend(b"\xff\xc0" + struct.pack(">H", len(sof) + 2) + sof)

        dc0 = HuffTable(STD_DC_BITS, STD_DC_VALUES)
        ac0 = HuffTable(STD_AC_BITS, STD_AC_VALUES)
        for cls, _table, bits, values in ((0, dc0, STD_DC_BITS, STD_DC_VALUES),
                                          (1, ac0, STD_AC_BITS, STD_AC_VALUES)):
            dht = bytearray((cls << 4,))
            dht.extend(bits)
            dht.extend(values)
            out.extend(b"\xff\xc4" + struct.pack(">H", len(dht) + 2) + dht)

        sos = bytearray((len(self.components),))
        for comp in self.components:
            sos.extend((comp["id"], 0x00))
        sos.extend((0, 63, 0))
        out.extend(b"\xff\xda" + struct.pack(">H", len(sos) + 2) + sos)

        writer = BitWriter()
        dc_pred = {c["index"]: 0 for c in self.components}
        mcu_rows = div_roundup(self.height, 8 * self.max_v)
        mcu_cols = div_roundup(self.width, 8 * self.max_h)
        for r in range(mcu_rows):
            for c in range(mcu_cols):
                for comp in self.components:
                    ci = comp["index"]
                    for y in range(comp["v"]):
                        for x in range(comp["h"]):
                            block = self.blocks[ci][r * comp["v"] + y][c * comp["h"] + x]
                            self._encode_block(writer, block, dc_pred, ci, dc0, ac0)
        out.extend(writer.flush())
        out.extend(b"\xff\xd9")
        return bytes(out)

    @staticmethod
    def _encode_block(writer: BitWriter, block: list[int], dc_pred: dict, ci: int,
                      dc_table: HuffTable, ac_table: HuffTable) -> None:
        diff = block[0] - dc_pred[ci]
        dc_pred[ci] = block[0]
        cat = _category(diff)
        code, length = dc_table.encode[cat]
        writer.put(code, length)
        if cat:
            writer.put(_value_bits(diff, cat), cat)

        run = 0
        for k in range(1, 64):
            value = block[ZIGZAG[k]]
            if value == 0:
                run += 1
                continue
            while run > 15:
                code, length = ac_table.encode[0xF0]
                writer.put(code, length)
                run -= 16
            cat = _category(value)
            symbol = (run << 4) | cat
            code, length = ac_table.encode[symbol]
            writer.put(code, length)
            writer.put(_value_bits(value, cat), cat)
            run = 0
        if run:
            code, length = ac_table.encode[0x00]
            writer.put(code, length)
