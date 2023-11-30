#!/usr/bin/env python3

"""Create/inspect OpenTitan Integrated flash images and bundles.
"""

# Copyright (c) 2023 Rivos, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from argparse import ArgumentParser, ArgumentTypeError, FileType
from binascii import hexlify, unhexlify
from hashlib import sha256 as hash_sha256
from os import stat
from struct import calcsize as scalc, pack as spack, unpack as sunpack
from sys import exit as sysexit
from typing import BinaryIO, Dict, Iterable, List, TextIO, Tuple

from elftools.elf.elffile import ELFError, ELFFile
from elftools.elf.constants import SH_FLAGS
from yaml import load as yaml_load, FullLoader as YAMLFullLoader


FLASH_VERSION_MAJOR = 0
FLASH_VERSION_MINOR = 1


def config_has_key(config: Dict[str, any], key: str, val_type: type) -> bool:
    if key not in config:
        return False
    if not isinstance(config[key], val_type):
        return False
    return True


class Tabulate:
    # pylint: disable=too-few-public-methods

    _SEP = '-'
    _SEP_CHARS = ('+-', '-+-', '-+')
    _LINE_CHARS = ('| ', ' | ', ' |')

    MAX_NAME_DISPLAY_LEN = 20

    def __init__(self, fmt: List[Tuple[str, str, int, str, str]]):
        sep = []
        header = []
        vfmt = []
        for (name, dispname, width, align, mod) in fmt:
            sep.append(self._SEP * width)
            header.append(f'{{:{align[-1:]}{width}}}'.format(dispname))
            vfmt.append(f'{{{name}:{align}{width}{mod}}}')
        self.sep = self._join_line(sep, self._SEP_CHARS)
        self.header = self._join_line(header, self._LINE_CHARS)
        self.vfmt = self._join_line(vfmt, self._LINE_CHARS)

    def print(self, data: Iterable):
        print(self.sep)
        print(self.header)
        for values in data:
            print(self.sep)
            print(self.vfmt.format(**values))
        print(self.sep)

    @staticmethod
    def _join_line(elems: List[str], seps: List[str]) -> str:
        return ''.join((seps[0], seps[1].join(elems), seps[2]))

    @classmethod
    def pretty_name(cls, name: str) -> str:
        if not name:
            return ''
        maxlen = cls.MAX_NAME_DISPLAY_LEN
        if len(name) <= maxlen:
            return name
        return ''.join(('…', name[-(maxlen - 1):]))


class Struct:
    @staticmethod
    def pack(fmt: Dict[str, str], values: Dict[str, any]) -> bytes:
        args = [values[k] for k in fmt]
        ffmt = ''.join(fmt.values())
        return spack(f'<{ffmt}', *args)

    @staticmethod
    def calc_size(fmt: Dict[str, str]) -> int:
        ffmt = ''.join(fmt.values())
        return scalc(f'<{ffmt}')

    @staticmethod
    def unpack(fmt: Dict[str, str], data: bytes) -> Dict[str, any]:
        ffmt = ''.join(fmt.values())
        values = sunpack(f'<{ffmt}', data)
        return dict(zip(fmt, values))


class Partition:
    # pylint: disable=too-many-instance-attributes

    TYPE_BUNDLE = 0
    TYPE_KEY_MANIFEST = 1
    TYPE_CUSTOM_START = 0x8000
    TYPE_CUSTOM_END = 0xFFFF

    def __init__(self, name: str, config: Dict):
        self._used = 0
        self._parse_config(name, config)

    def _parse_config(self, name: str, config: Dict):
        # pylint: disable=too-many-branches
        self._file = None
        self._name = name
        if not config_has_key(config, 'offset', int):
            raise ValueError('Partition must contain an integer field "offset"')
        self._offset = config['offset']
        if not config_has_key(config, 'size', int):
            raise ValueError('Partition must contain an integer field "size"')
        self._size = config['size']
        if not config_has_key(config, 'ident', str):
            raise ValueError('Partition must contain a string field "ident"')
        self._ident = config['ident'].encode()
        if len(self._ident) != 4:
            raise ValueError('Partition identifier must be a 4-char ASCII string')
        if config_has_key(config, 'slot', int):
            self._slot = config['slot']
        else:
            self._slot = 0
        if config_has_key(config, 'type', str):
            self._ptype = config['type']
            if self._ptype == 'bundle':
                self._ptype = self.TYPE_BUNDLE
            elif self._ptype == 'key_manifest':
                self._ptype = self.TYPE_KEY_MANIFEST
            else:
                raise ValueError(f'Invalid partition type "{self._ptype}"')
        elif config_has_key(config, 'type', int):
            self._ptype = config['type']
            if self._ptype < self.TYPE_CUSTOM_START or self._ptype > self.TYPE_CUSTOM_END:
                raise ValueError(f'Invalid custom partition type 0x{self._ptype:0>4x},'
                                 ' should be >= 0x8000')
        else:
            raise ValueError('Partition must contain a integer or string field "type"')

    @property
    def name(self) -> str:
        return self._name

    @property
    def ident(self) -> bytes:
        return self._ident

    @property
    def ptype(self) -> int:
        return self._ptype

    @property
    def slot(self) -> int:
        return self._slot

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def size(self) -> int:
        return self._size

    @property
    def file(self) -> BinaryIO:
        return self._file

    @file.setter
    def file(self, file):
        self._file = file

    @property
    def used(self) -> int:
        if not self._used and self._file is not None:
            self._used = stat(self._file.fileno()).st_size
        return self._used


class Flash:
    PART_TABLE_HEADER_FORMAT = {
        'magic_number': '4s',  # "OTPT"
        'version_major': 'H',  # 0
        'version_minor': 'H',  # 1
        'part_count': 'I',     # count of partitions
    }

    PART_ENTRY_FORMAT = {
        'identifier': '4s',    # identifier
        'type': 'H',           # type
        'slot_number': 'H',    # slot number
        'start_address': 'I',  # start offset in flash
        'size': 'I',           # size
    }

    PRETTY_PRINT_PART_FORMAT = (
        ('name', 'Name', Tabulate.MAX_NAME_DISPLAY_LEN, '<', ''),
        ('ident', 'Ident', 5, '<', ''),
        ('type', 'Type', 12, '<', ''),
        ('slot', 'Slot', 4, '>', ''),
        ('offset', 'Start', 8, '0>', 'x'),
        ('end', 'End', 8, '0>', 'x'),
        ('size', 'Size', 8, '>', ''),
        ('used', 'Used', 8, '>', ''),
        ('filename', 'File Name', Tabulate.MAX_NAME_DISPLAY_LEN, '<', ''),
    )

    def __init__(self, config: Dict):
        self._flash_size = 0
        self._block_align = 0
        self._partitions = {}
        self._content = None
        self._parse_config(config)
        self._sanity_check()

    def _parse_config(self, config: Dict):
        if not config_has_key(config.get('global', {}), 'flash_size', int):
            raise ValueError('"global" must contain an int field "flash_size"')
        self._flash_size = config['global']['flash_size']
        if not config_has_key(config.get('global', {}), 'block_align', int):
            raise ValueError('"global" must contain an int field "block_align"')
        self._block_align = config['global']['block_align']
        self._partitions = {}
        for partname, partconfig in config.get('partitions', {}).items():
            part = Partition(partname, partconfig)
            part_ident = (part.ident, part.slot)
            if part_ident in self._partitions:
                duplicate = self._partitions[part_ident]
                raise ValueError(f'Partition "{part.name}" is a duplicate of "{duplicate.name}"')
            self._partitions[part_ident] = part

    @staticmethod
    def _is_power_of_2(num: int):
        return (num & (num - 1) == 0) and num != 0

    def _check_alignment(self, val: int, desc: str, non_zero: bool = False):
        if val & (self._block_align - 1) != 0:
            raise ValueError(f'{desc} must be aligned on block size')
        if non_zero and val == 0:
            raise ValueError(f'{desc} must be non-zero')

    def _sanity_check(self):
        # check block align is a power of 2
        if not self._is_power_of_2(self._block_align):
            raise ValueError('Flash block alignment must be a power of 2')
        # check global settings
        self._check_alignment(self._flash_size, 'Flash size', non_zero=True)
        # compute partition table size
        part_table_size = Struct.calc_size(self.PART_TABLE_HEADER_FORMAT) + \
            len(self._partitions) * Struct.calc_size(self.PART_ENTRY_FORMAT)
        # check partitions
        previous = ('', -1)
        for part in sorted(self._partitions.values(), key=lambda part: part.offset):
            if part.offset < part_table_size:
                raise ValueError(f'Partition "{part.name}" overlaps partition table')
            self._check_alignment(part.offset, f'Partition "{part.name}" offset')
            self._check_alignment(part.size, f'Partition "{part.name}" size',
                                  non_zero=True)
            if part.offset <= previous[1]:
                raise ValueError(f'Partition "{part.name}" overlaps partition "{previous[0]}"')
            previous = (part.name, part.offset + part.size - 1)

    @staticmethod
    def _pretty_part_type(ptype: int) -> str:
        if ptype == Partition.TYPE_BUNDLE:
            return 'Bundle'
        if ptype == Partition.TYPE_KEY_MANIFEST:
            return 'Key Manifest'
        return f'Custom[{ptype:0>4x}]'

    @classmethod
    def _pretty_file(cls, file: BinaryIO) -> str:
        return Tabulate.pretty_name(file.name if file else None)

    def print_partitions(self):
        tab = Tabulate(self.PRETTY_PRINT_PART_FORMAT)
        tab.print(map(lambda part: {'name': Tabulate.pretty_name(part.name),
                                    'ident': part.ident.decode(),
                                    'type': self._pretty_part_type(part.ptype),
                                    'slot': part.slot,
                                    'offset': part.offset,
                                    'end': part.offset + part.size,
                                    'size': part.size,
                                    'used': part.used,
                                    'filename': self._pretty_file(part.file)},
                      sorted(self._partitions.values(), key=lambda part: part.offset)))

    def _create_part_table(self) -> bytes:
        part_table = []
        values = {'magic_number': b'OTPT', 'version_major': FLASH_VERSION_MAJOR,
                  'version_minor': FLASH_VERSION_MINOR, 'part_count': len(self._partitions)}
        part_table.append(Struct.pack(self.PART_TABLE_HEADER_FORMAT, values))
        for part in sorted(self._partitions.values(), key=lambda part: part.offset):
            values = {'identifier': part.ident, 'type': part.ptype,
                      'slot_number': part.slot, 'start_address': part.offset, 'size': part.size}
            part_table.append(Struct.pack(self.PART_ENTRY_FORMAT, values))
        return b''.join(part_table)

    def collect_data(self) -> bytes:
        data = bytearray(b'\xff' * self._flash_size)
        part_table = self._create_part_table()
        if len(part_table) > self._flash_size:
            raise ValueError('Partition table does not fit')
        data[0:len(part_table)] = part_table
        for part in self._partitions.values():
            if part.used != 0:
                print(f'Reading data for partition "{part.name}" from {part.file.name}')
                if part.used > part.size:
                    raise ValueError(
                            f'File {part.file.name} does not fit into partition "{part.name}"')
                partdata = part.file.read()
                data[part.offset:part.offset + len(partdata)] = partdata
        return data

    def link_files(self, partitions: List[Tuple[str, str, BinaryIO]]):
        if partitions:
            for ident, slot, file in partitions:
                partident = (ident, slot)
                if partident not in self._partitions:
                    raise ValueError(f'No known partition with ident "{ident}" slot {slot}')
                self._partitions[partident].file = file

    @staticmethod
    def generate(config: TextIO, partitions: List[Tuple[str, str, BinaryIO]], outfile: BinaryIO):
        print(f'Loading flash config "{config.name}"')
        flash = Flash(yaml_load(config, Loader=YAMLFullLoader))
        flash.link_files(partitions)
        flash.print_partitions()
        print('Collecting partition data')
        data = flash.collect_data()
        print(f'Writing flash image to "{outfile.name}"')
        outfile.write(data)

    @classmethod
    def inspect(cls, infile: BinaryIO):
        print(f'Inspecting flash image "{infile.name}"')

        header = infile.read(Struct.calc_size(cls.PART_TABLE_HEADER_FORMAT))
        header = Struct.unpack(cls.PART_TABLE_HEADER_FORMAT, header)
        if header['magic_number'] != b'OTPT':
            raise ValueError('Invalid partition table magic number')
        if header['version_major'] != FLASH_VERSION_MAJOR or \
           header['version_minor'] != FLASH_VERSION_MINOR:
            raise ValueError('Invalid partition table version')
        part_count = header['part_count']
        print(f'Image contains {part_count} partition(s)')

        entry_size = Struct.calc_size(cls.PART_ENTRY_FORMAT)
        partitions = []
        for idx in range(part_count):
            entry = infile.read(entry_size)
            part = Struct.unpack(cls.PART_ENTRY_FORMAT, entry)
            partitions.append(part)
            ptype = part['type']
            if ptype in (Partition.TYPE_BUNDLE, Partition.TYPE_KEY_MANIFEST):
                continue
            if ptype < Partition.TYPE_CUSTOM_START or ptype > Partition.TYPE_CUSTOM_END:
                raise ValueError(f'Partition #{idx} has invalid type 0x{ptype:0>4x}')

        tab = Tabulate(cls.PRETTY_PRINT_PART_FORMAT[1:-2])
        tab.print(map(lambda part: {'ident': part['identifier'].decode(),
                                    'type': cls._pretty_part_type(part['type']),
                                    'slot': part['slot_number'],
                                    'offset': part['start_address'],
                                    'end': part['start_address'] + part['size'],
                                    'size': part['size']},
                      sorted(partitions, key=lambda part: part['start_address'])))


class Asset:
    TYPE_RAW_DATA = 0
    TYPE_FIRMWARE = 1
    TYPE_CUSTOM_START = 0x8000
    TYPE_CUSTOM_END = 0xFFFF

    def __init__(self, ident: bytes, atype: str, file: BinaryIO):
        self._ident = ident
        self._atype = atype
        self._file = file
        self._data = None

    @property
    def ident(self) -> bytes:
        return self._ident

    @property
    def atype(self) -> int:
        return self._atype

    @property
    def size(self) -> int:
        return stat(self._file.fileno()).st_size

    @property
    def digest(self) -> bytes:
        return hash_sha256(self.data).digest()

    @property
    def filename(self) -> str:
        return self._file.name

    @property
    def data(self) -> bytes:
        if self._data:
            return self._data
        self._data = self._file.read()
        return self._data


class Bundle:
    KEY_OWNERS = ["Silicon Creator", "Silicon Owner", "Platform Integrator", "Platform Owner"]

    BUNDLE_SIG_HEADER_FORMAT = {
        'signature_count': 'I',  # count of signatures
    }

    BUNDLE_SIG_ENTRY_FORMAT = {
        'signature': '96s',  # signature
        'key_owner': 'I',    # key owner
    }

    USAGE_CONSTRAINTS_FORMAT = {
        'selector_bits': 'I',       # selector bits
        'device_id': '8s',          # DEVICE_ID (selector bits 0-7)
        'manuf_state_creator': 'I', # CREATOR_SW_MANUF_STATUS (selector bit 8)
        'manuf_state_owner': 'I',   # OWNER_SW_MANUF_STATUS (selector bit 9)
        'life_cycle_state': 'I',    # Device life cycle status (selector bit 10)
    }

    USAGE_CONSTRAINT_UNSELECTED_WORD = 0xA5A5A5A5

    BUNDLE_MANIFEST_HEADER_FORMAT = {
        'version_major': 'H',        # 0
        'version_minor': 'H',        # 1
        'usage_constraints': '48s',  # usage constraints (placeholder)
        'security_version': 'I',     # security version
        'timestamp': 'Q',            # timestamp
        'binding_value': '32s',      # binding value
        'max_key_version': 'I',      # max_key_version
        'asset_count': 'I',          # count of assets
    }

    BUNDLE_ASSET_MANIFEST_FORMAT = {
        'identifier': '4s',          # identifier
        'digest': '32s',             # SHA256 digest
        'reserved': 'H',             # (reserved)
        'asset_type': 'H',           # asset type
        'start': 'I',                # start offset from the start of the bundle manifest
        'size': 'I',                 # size
    }

    PRETTY_PRINT_ASSET_MIN_FORMAT = (
        ('ident', 'Ident', 5, '<', ''),
        ('type', 'Type', 12, '<', ''),
        ('size', 'Size', 8, '>', ''),
        ('filename', 'File Name', Tabulate.MAX_NAME_DISPLAY_LEN, '<', ''),
    )

    PRETTY_PRINT_SIG_FORMAT = (
        ('signature', 'Signature', 15, '>', ''),
        ('key_owner', 'Key Owner', 19, '>', ''),
    )

    PRETTY_PRINT_MANIFEST_FORMAT = (
        ('svn', 'SVN', 5, '>', ''),
        ('timestamp', 'Timestamp', 12, '>', ''),
        ('binding', 'Binding', 15, '>', ''),
        ('max_key_ver', 'Max Key Ver', 11, '>', ''),
    )

    PRETTY_PRINT_ASSET_FORMAT = (
        ('ident', 'Ident', 5, '<', ''),
        ('type', 'Type', 14, '<', ''),
        ('offset', 'Start', 8, '0>', 'x'),
        ('end', 'End', 8, '0>', 'x'),
        ('size', 'Size', 8, '>', 'x'),
        ('digest', 'Digest', 13, '>', ''),
    )

    def __init__(self, config: Dict, assets: List[Tuple[bytes, str, BinaryIO]]):
        self._usage_constraints = {
            'selector_bits': 0,
            'device_id': bytes([self.USAGE_CONSTRAINT_UNSELECTED_WORD & 0xff]) * 8,
            'manuf_state_creator': self.USAGE_CONSTRAINT_UNSELECTED_WORD,
            'manuf_state_owner': self.USAGE_CONSTRAINT_UNSELECTED_WORD,
            'life_cycle_state': self.USAGE_CONSTRAINT_UNSELECTED_WORD}
        self._security_version = 0
        self._timestamp = 0
        self._binding_value = bytes(32)
        self._max_key_version = 0
        self._assets = []

        if config_has_key(config, 'svn', int):
            self._security_version = config['svn']
        if config_has_key(config, 'timestamp', int):
            self._timestamp = config['timestamp']
        if config_has_key(config, 'binding', bytes):
            self._binding_value = config['binding']
        if config_has_key(config, 'max_key_ver', int):
            self._max_key_version = config['max_key_ver']

        self._assets.extend(assets)

    @staticmethod
    def _pretty_asset_type(atype: int) -> str:
        if atype == Asset.TYPE_RAW_DATA:
            return 'Raw Data'
        if atype == Asset.TYPE_FIRMWARE:
            return 'Firmware'
        if atype < Asset.TYPE_CUSTOM_START or atype > Asset.TYPE_CUSTOM_END:
            return f'Custom[{atype:0>4x}]'
        return f'Reserved[{atype:0>4x}]'

    @classmethod
    def _pretty_key_owner(cls, key_owner: int) -> str:
        if key_owner < len(cls.KEY_OWNERS):
            return cls.KEY_OWNERS[key_owner]
        return f'Reserved[{key_owner:0>4x}]'

    @staticmethod
    def _pretty_bytes(data: bytes) -> str:
        return '…'.join((hexlify(data[:3]).decode("ascii"),
                         hexlify(data[-3:]).decode("ascii")))

    def print_assets(self):
        tab = Tabulate(self.PRETTY_PRINT_ASSET_MIN_FORMAT)
        tab.print(map(lambda asset: {'ident': asset.ident.decode(),
                                     'type': self._pretty_asset_type(asset.atype),
                                     'size': asset.size,
                                     'filename': Tabulate.pretty_name(asset.filename)},
                      self._assets))

    def write(self, outfile: BinaryIO) -> bytes:
        # always no signatures at this point
        # bundle will be signed with a second call to the tool

        # write signature header
        values = {'signature_count': 0}
        outfile.write(Struct.pack(self.BUNDLE_SIG_HEADER_FORMAT, values))

        # record start of bundle manifest
        bundle_start = stat(outfile.fileno()).st_size

        # write bundle manifest
        values = {'version_major': FLASH_VERSION_MAJOR,
                  'version_minor': FLASH_VERSION_MINOR,
                  'usage_constraints': Struct.pack(self.USAGE_CONSTRAINTS_FORMAT,
                                                   self._usage_constraints),
                  'security_version': self._security_version,
                  'timestamp': self._timestamp,
                  'binding_value': self._binding_value,
                  'max_key_version': self._max_key_version,
                  'asset_count': len(self._assets)}
        outfile.write(Struct.pack(self.BUNDLE_MANIFEST_HEADER_FORMAT, values))

        # write asset manifests
        asset_data_start = Struct.calc_size(self.BUNDLE_MANIFEST_HEADER_FORMAT) \
            + Struct.calc_size(self.BUNDLE_ASSET_MANIFEST_FORMAT) * len(self._assets)
        for asset in self._assets:
            values = {'identifier': asset.ident,
                      'digest': asset.digest[::-1], ## output LSB first
                      'reserved': 0,
                      'asset_type': asset.atype,
                      'start': asset_data_start - bundle_start,
                      'size': asset.size}
            outfile.write(Struct.pack(self.BUNDLE_ASSET_MANIFEST_FORMAT, values))
            asset_data_start = asset_data_start + asset.size

        # write asset data
        for asset in self._assets:
            outfile.write(asset.data)

    @staticmethod
    def generate(config: Dict[str, any],
                 assets: List[Tuple[str, str, BinaryIO]],
                 outfile: BinaryIO):
        bundle = Bundle(config, assets)
        bundle.print_assets()
        print(f'Collecting asset data and writing bundle to "{outfile.name}"')
        bundle.write(outfile)

    @classmethod
    def inspect(cls, infile: BinaryIO):
        print(f'Inspecting bundle "{infile.name}"')

        # signature header
        sig_header = infile.read(Struct.calc_size(cls.BUNDLE_SIG_HEADER_FORMAT))
        sig_header = Struct.unpack(cls.BUNDLE_SIG_HEADER_FORMAT, sig_header)
        sig_count = sig_header['signature_count']
        print(f'Bundle signed with {sig_count} signature(s)')

        # signatures
        if sig_count:
            signature_size = Struct.calc_size(cls.BUNDLE_SIG_ENTRY_FORMAT)
            signatures = []
            for _ in range(sig_count):
                sig = infile.read(signature_size)
                sig = Struct.unpack(cls.BUNDLE_SIG_ENTRY_FORMAT, sig)
                signatures.append(sig)
            tab = Tabulate(cls.PRETTY_PRINT_SIG_FORMAT)
            tab.print(map(lambda sig: {'signature': cls._pretty_bytes(sig['signature']),
                                       'key_owner': cls._pretty_key_owner(sig['key_owner'])},
                          signatures))

        # bundle manifest
        mf_header = infile.read(Struct.calc_size(cls.BUNDLE_MANIFEST_HEADER_FORMAT))
        mf_header = Struct.unpack(cls.BUNDLE_MANIFEST_HEADER_FORMAT, mf_header)
        tab = Tabulate(cls.PRETTY_PRINT_MANIFEST_FORMAT)
        tab.print(map(lambda hdr: {'svn': hdr['security_version'],
                                   'timestamp': hdr['timestamp'],
                                   'binding': cls._pretty_bytes(hdr['binding_value']),
                                   'max_key_ver': hdr['max_key_version']}, [mf_header]))
        asset_count = mf_header['asset_count']
        print(f'Bundle contains {asset_count} asset(s)')

        # asset manifests
        if asset_count:
            asset_mf_size = Struct.calc_size(cls.BUNDLE_ASSET_MANIFEST_FORMAT)
            assets = []
            for _ in range(asset_count):
                asset_mf = infile.read(asset_mf_size)
                asset_mf = Struct.unpack(cls.BUNDLE_ASSET_MANIFEST_FORMAT, asset_mf)
                assets.append(asset_mf)
                atype = asset_mf['asset_type']
                if atype in (Asset.TYPE_RAW_DATA, Asset.TYPE_FIRMWARE):
                    continue

            tab = Tabulate(cls.PRETTY_PRINT_ASSET_FORMAT)
            tab.print(map(lambda asset: {'ident': asset['identifier'].decode(),
                                         'type': cls._pretty_asset_type(asset['asset_type']),
                                         'offset': asset['start'],
                                         'end': asset['start'] + asset['size'],
                                         'size': asset['size'],
                                         'digest': cls._pretty_bytes(asset['digest'])}, assets))


class FirmwareSegment:
    # pylint: disable=too-few-public-methods

    def __init__(self, addr: int):
        self._addr = addr

    @property
    def addr(self) -> int:
        return self._addr


class FirmwareLoadableSegment(FirmwareSegment):
    def __init__(self, addr: int, data: bytes):
        super().__init__(addr)
        self._data = data

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def size(self) -> int:
        return len(self._data)

    @property
    def type(self) -> str:
        return "LOAD"


class FirmwarePaddingSegment(FirmwareSegment):
    def __init__(self, addr: int, size: int):
        super().__init__(addr)
        self._size = size

    @property
    def data(self) -> bytes:
        return bytes(self._size)

    @property
    def size(self) -> int:
        return self._size

    @property
    def type(self) -> str:
        return "PAD"


class Firmware:
    FIRMWARE_DESC_FORMAT = {
        'entry_point': 'I',  # entry_point
        'code_start': 'I',   # start of executable section
        'code_end': 'I',     # end of executable section
    }

    PRETTY_PRINT_FIRMWARE_FORMAT = (
        ('entry_point', 'Entry', 8, '>', 'x'),
        ('code_start', 'CodeStart', 9, '>', 'x'),
        ('code_end', 'CodeEnd', 8, '>', 'x'),
    )

    PRETTY_PRINT_SEGMENT_FORMAT = (
        ('type', 'Type', 8, '<', ''),
        ('address', 'Addr', 8, '>', 'x'),
        ('size', 'Size', 8, '>', 'x'),
    )

    def __init__(self, elffile: BinaryIO):
        self._filename = elffile.name
        try:
            self._elf = ELFFile(elffile)
        except ELFError as exc:
            raise ValueError(f'Invalid ELF file: {exc}') from exc
        if self._elf['e_machine'] != 'EM_RISCV':
            raise ValueError('Not a RISC-V ELF file')
        if self._elf['e_ident']['EI_CLASS'] != 'ELFCLASS32':
            raise ValueError('Not a 32-bit ELF file')
        if self._elf['e_type'] != 'ET_EXEC':
            raise ValueError('Not an executable ELF file')
        self._entry_point, self._segments = self._loadable_segments()
        self._code_start, self._code_end = self._code_region()

    def _code_region(self):
        code_start = None
        code_end = None
        for sec in sorted(filter(lambda s: s['sh_flags'] & SH_FLAGS.SHF_EXECINSTR != 0,
                                 self._elf.iter_sections()), key=lambda s: s['sh_addr']):
            sec_start = sec['sh_addr']
            sec_end = sec_start + sec['sh_size']
            if not code_start:
                code_start = sec_start
            if code_end is None or sec_end > code_end:
                code_end = sec_end
        return (code_start, code_end)

    def _loadable_segments(self):
        entry_point = self._elf['e_entry']
        segments = []
        curr_addr = None
        for elf_seg in sorted(filter(lambda s: s['p_type'] == 'PT_LOAD' and s['p_filesz'] != 0,
                                     self._elf.iter_segments()),
                              key=lambda s: s['p_paddr']):
            p_paddr = elf_seg['p_paddr']
            if curr_addr is not None and p_paddr > curr_addr:
                padding_size = p_paddr - curr_addr
                seg = FirmwarePaddingSegment(curr_addr, padding_size)
                segments.append(seg)
                curr_addr = seg.addr + seg.size
            seg = FirmwareLoadableSegment(p_paddr, elf_seg.data())
            segments.append(seg)
            curr_addr = seg.addr + seg.size
        return (entry_point, segments)

    def print_info(self):
        print(f'Processing file "{self._filename}":')
        values = {'entry_point': self._entry_point,
                  'code_start': self._code_start,
                  'code_end': self._code_end}
        tab = Tabulate(self.PRETTY_PRINT_FIRMWARE_FORMAT)
        tab.print([values])
        print('Loadable Segments:')
        tab = Tabulate(self.PRETTY_PRINT_SEGMENT_FORMAT)
        tab.print(map(lambda seg: {'type': seg.type,
                                   'address': seg.addr,
                                   'size': seg.size},
                      self._segments))

    def write(self, outfile: BinaryIO) -> bytes:
        # write firmware descriptor
        values = {'entry_point': self._entry_point,
                  'code_start': self._code_start,
                  'code_end': self._code_end}
        outfile.write(Struct.pack(self.FIRMWARE_DESC_FORMAT, values))
        for seg in self._segments:
            outfile.write(seg.data)

    @staticmethod
    def generate(elffile: BinaryIO, outfile: BinaryIO):
        firmware = Firmware(elffile)
        firmware.print_info()
        print(f'Writing firmware image to "{outfile.name}"')
        firmware.write(outfile)

    @classmethod
    def inspect(cls, infile: BinaryIO):
        print(f'Inspecting firmware image "{infile.name}"')

        # firmware descriptor
        desc = infile.read(Struct.calc_size(cls.FIRMWARE_DESC_FORMAT))
        desc = Struct.unpack(cls.FIRMWARE_DESC_FORMAT, desc)
        tab = Tabulate(cls.PRETTY_PRINT_FIRMWARE_FORMAT)
        tab.print([desc])


def cli_flash(args):
    if args.generate and args.inspect:
        print('Cannot use --generate/-g and --inspect/-i at the same time')
        sysexit(1)
    if args.generate:
        Flash.generate(args.config, args.partitions, args.generate)
    elif args.inspect:
        if args.config:
            print('Option --config/-c ignored in "inspect" mode')
        if args.partitions:
            print('Option --part/-p ignored in "inspect" mode')
        Flash.inspect(args.inspect)


def cli_bundle(args):
    if args.generate and args.inspect:
        print('Cannot use --generate/-g and --inspect/-i at the same time')
        sysexit(1)
    if args.generate:
        config = {}
        if args.svn:
            config['svn'] = args.svn
        if args.timestamp:
            config['timestamp'] = args.timestamp
        if args.binding:
            config['binding'] = args.binding
        if args.max_key_ver:
            config['max_key_ver'] = args.max_key_ver
        Bundle.generate(config, args.assets, args.generate)
    elif args.inspect:
        if args.svn:
            print('Option --svn/-s ignored in "inspect" mode')
        if args.timestamp:
            print('Option --timestamp/-t ignored in "inspect" mode')
        if args.binding:
            print('Option --binding/-b ignored in "inspect" mode')
        if args.max_key_ver:
            print('Option --max_key_ver/-k ignored in "inspect" mode')
        if args.assets:
            print('Option --asset/-a ignored in "inspect" mode')
        Bundle.inspect(args.inspect)


def cli_firmware(args):
    if args.generate and args.inspect:
        print('Cannot use --generate/-g and --inspect/-i at the same time')
        sysexit(1)
    if args.generate:
        Firmware.generate(args.elf, args.generate)
    elif args.inspect:
        if args.elf:
            print('Option --elf/-e ignored in "inspect" mode')
        Firmware.inspect(args.inspect)


def partition_arg_type(value: str):
    # pylint: disable=raise-missing-from
    # pylint: disable=consider-using-with
    if value.find(':') == -1:
        raise ArgumentTypeError('Invalid partition format, expected ident[:slot]:filename')
    ident, rest = value.split(':', 1)
    ident = ident.encode()
    if len(ident) != 4:
        raise ArgumentTypeError('ident must be 4-char ASCII string')
    if rest.find(':') != -1:
        slot, filename = rest.split(':', 1)
        try:
            slot = int(slot)
        except ValueError:
            raise ArgumentTypeError('slot must be a number')
    else:
        slot = 0
        filename = rest
    try:
        file = open(filename, 'rb')
    except Exception as exc:
        raise ArgumentTypeError(f'can\'t open "{filename}": {exc}')
    return (ident, slot, file)


def asset_arg_type(value: str):
    # pylint: disable=raise-missing-from
    # pylint: disable=consider-using-with
    try:
        ident, atype, filename = value.split(':', 3)
    except ValueError:
        raise ArgumentTypeError('Invalid asset format, expected ident:type:filename')
    ident = ident.encode()
    if len(ident) != 4:
        raise ArgumentTypeError('ident must be 4-char ASCII string')
    if atype == 'raw_data':
        atype = Asset.TYPE_RAW_DATA
    elif atype == 'firmware':
        atype = Asset.TYPE_FIRMWARE
    else:
        try:
            atype = int(atype)
        except ValueError:
            raise ArgumentTypeError('asset type must be "raw_data", "firmware" or a number')
        if atype < Asset.TYPE_CUSTOM_START or atype > Asset.TYPE_CUSTOM_END:
            raise ArgumentTypeError(f'custom asset type 0x{atype:0>4x} must be >= 0x8000')
    try:
        file = open(filename, 'rb')
    except Exception as exc:
        raise ArgumentTypeError(f'can\'t open "{filename}": {exc}')
    if stat(file.fileno()).st_size & 3 != 0:
        raise ArgumentTypeError('asset size must be a multiple of 4 bytes')
    return Asset(ident, atype, file)


def binding_arg_type(value: str):
    # pylint: disable=raise-missing-from
    try:
        value = unhexlify(value)
        if len(value) != 32:
            raise ValueError('not 32 bytes long')
    except ValueError:
        raise ArgumentTypeError('binding value type must be a 32-bytes hex string')
    return value


def cli():
    parser = ArgumentParser(description='Create and inspect flash images/assets')
    subparsers = parser.add_subparsers(
        help='Command', dest='cmd', required=True
    )

    flash = subparsers.add_parser('flash', help='Generate/Inspect a flash image')
    flash_gen = flash.add_argument_group(title='Generation')
    flash_gen.add_argument(
        '-g', '--generate', metavar='RAW', type=FileType('wb'),
        help='Flash image file to generate',
    )
    flash_gen.add_argument(
        '-c', '--config', metavar='CFG', type=FileType('rt', encoding='utf-8'),
        help='Configuration file (yaml)',
    )
    flash_gen.add_argument(
        '-p', '--part', metavar='IDENT[:SLOT]:FILE', type=partition_arg_type, action='append',
        dest='partitions', help='Partition content'
    )
    flash_insp = flash.add_argument_group(title='Inspection')
    flash_insp.add_argument(
        '-i', '--inspect', metavar='RAW', type=FileType('rb'),
        help='Flash image file to inspect')
    flash.set_defaults(func=cli_flash)

    bundle = subparsers.add_parser('bundle', help='Generate/Inspect a flash bundle')
    bundle_gen = bundle.add_argument_group(title='Generation')
    bundle_gen.add_argument(
        '-g', '--generate', metavar='RAW', type=FileType('wb'),
        help='Bundle file to generate',
    )
    bundle_gen.add_argument(
        '-s', '--svn', metavar='VERSION', type=int,
        help='Bundle security version',
    )
    bundle_gen.add_argument(
        '-t', '--timestamp', metavar='TIMESTAMP', type=int,
        help='Bundle timestamp',
    )
    bundle_gen.add_argument(
        '-b', '--binding', metavar='HEX', type=binding_arg_type,
        help='Bundle binding value (32-bytes hex string)',
    )
    bundle_gen.add_argument(
        '-k', '--max_key_ver', metavar='VER', type=int,
        help='Bundle Max Key Version',
    )
    bundle_gen.add_argument(
        '-a', '--asset', metavar='IDENT:TYPE:FILE', type=asset_arg_type, action='append',
        dest='assets', help='Asset content'
    )
    bundle_insp = bundle.add_argument_group(title='Inspection')
    bundle_insp.add_argument(
        '-i', '--inspect', metavar='RAW', type=FileType('rb'),
        help='Flash bundle file to inspect')
    bundle.set_defaults(func=cli_bundle)

    firmware = subparsers.add_parser('firmware', help='Generate/Inspect a firmware image')
    firmware_gen = firmware.add_argument_group(title='Generation')
    firmware_gen.add_argument(
        '-g', '--generate', metavar='BIN', type=FileType('wb'),
        help='Firmware image file to generate',
    )
    firmware_gen.add_argument(
        '-e', '--elf', metavar='ELF', type=FileType('rb'),
        help='Input firmware ELF file to inspect')
    firmware_insp = firmware.add_argument_group(title='Inspection')
    firmware_insp.add_argument(
        '-i', '--inspect', metavar='BIN', type=FileType('rb'),
        help='Firmware image file to inspect')
    firmware.set_defaults(func=cli_firmware)

    args = parser.parse_args()

    # execute the function associated with the command
    args.func(args)


if __name__ == '__main__':
    cli()
