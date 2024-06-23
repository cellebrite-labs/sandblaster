#!/usr/bin/env python

"""
iOS/OS X sandbox decompiler

Heavily inspired from Dion Blazakis' previous work
    https://github.com/dionthegod/XNUSandbox/tree/master/sbdis
Excellent information from Stefan Essers' slides and work
    http://www.slideshare.net/i0n1c/ruxcon-2014-stefan-esser-ios8-containers-sandboxes-and-entitlements
    https://github.com/sektioneins/sandbox_toolkit
"""

import sys
import struct
import logging.config
import argparse
import os
from dataclasses import dataclass
from enum import IntEnum
from typing import IO, Self, Type, Generator

import operation_node
import sandbox_filter
import sandbox_regex
import subprocess
from abc import ABC, abstractmethod
from filters import Filters

REGEX_TABLE_OFFSET = 2
REGEX_COUNT_OFFSET = 4
VARS_TABLE_OFFSET = 6
VARS_COUNT_OFFSET = 8
NUM_PROFILES_OFFSET = 10

logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)

OPERATION_NODE_SIZE = 8
INDEX_SIZE = 2


class ProfileType(IntEnum):
    NORMAL = 0
    PROFILE_BUNDLE = 0x8000


@dataclass
class SandboxHeader:
    profile_type: ProfileType
    op_nodes_count: int
    sb_ops_count: int
    vars_count: int
    states_count: int


@dataclass
class SandboxHeader16_5(SandboxHeader):
    num_profiles: int
    regex_count: int
    entitlements_count: int


@dataclass
class SandboxHeader18_0(SandboxHeader):
    profile_flags: int
    num_profiles: int
    regex_count: int
    entitlements_count: int


class SandboxData(ABC):
    def __init__(self, args: argparse.Namespace, sb_ops: list[str]):
        self._args = args
        self._keep_builtin_filters: bool = args.keep_builtin_filters
        self._profiles_to_reverse: list[str] | None = args.profiles_to_reverse
        self._c_output: bool = args.c_output
        self._macho: bool = args.macho
        self._output_directory: str = args.output_directory
        self.data_file: IO = args.input_file

        # Header
        self._sandbox_header: SandboxHeader | None = None
        self._header_size: int = self.HEADER_STRUCT.size

        # Offsets
        self.regex_table_offset: int = 0
        self.vars_offset: int = 0
        self.states_offset: int = 0
        self.entitlements_offset: int = 0
        self.profiles_offset: int = 0
        self.profiles_end_offset: int = 0
        self.operation_nodes_size: int = 0
        self.operation_nodes_offset: int = 0
        self.base_addr: int = 0

        # Parse data structures
        self.regex_list: list = []  # TODO: list of what..?
        self.global_vars: list[str] = []
        self.policies: list = []  # TODO: list of what..?
        self.sb_ops: list[str] = sb_ops  # The list of sandbox operations was already read in parse_args method earlier
        self.operation_nodes: list[operation_node.OperationNode] = []
        self.ops_to_reverse: list[str] = args.ops_to_reverse

        # Step1: Parse the sandbox header according to the iOS version
        self.sandbox_header = self._parse_header()
        assert self.sandbox_header, 'Sandbox header parsing failed..'

        # Step2: Set offsets accordingly
        self._parse_offsets()

    @property
    @abstractmethod
    def HEADER_STRUCT(self) -> struct.Struct:
        """
        The sandbox header structure may differ between iOS versions so this is an abstract property
        """
        pass

    @property
    @abstractmethod
    def HEADER_CLS(self) -> Type[SandboxHeader]:
        """
        The sandbox header structure may differ between iOS versions so this is an abstract property
        """
        pass

    @property
    @abstractmethod
    def PROFILE_SIZE(self) -> int:
        """
        The sandbox profile size may differ between iOS versions so this is an abstract property
        """
        pass

    @property
    @abstractmethod
    def PROFILE_OPS_OFFSET(self) -> int:
        """
        The sandbox profile op_table offset may differ between iOS versions so this is an abstract property
        """
        pass

    def _parse_offsets(self):
        """
        TODO: Actually now this is not an abstract method.. should it be?
        The structure of the packed profile bundle may also differ between iOS versions therefore this function is
        abstract and the implementation should be provided by subclasses
        """
        self.sandbox_header: SandboxHeader16_5
        self.regex_table_offset = self._header_size
        self.vars_offset = self.regex_table_offset + (self.sandbox_header.regex_count * INDEX_SIZE)
        self.states_offset = self.vars_offset + (self.sandbox_header.vars_count * INDEX_SIZE)
        self.entitlements_offset = self.states_offset + (self.sandbox_header.states_count * INDEX_SIZE)

        self.profiles_offset = self.entitlements_offset + (self.sandbox_header.entitlements_count * INDEX_SIZE)
        self.profiles_end_offset = self.profiles_offset + (self.sandbox_header.num_profiles * self.PROFILE_SIZE)
        self.operation_nodes_size = self.sandbox_header.op_nodes_count * OPERATION_NODE_SIZE
        self.operation_nodes_offset = self.profiles_end_offset

        if not self.is_profile_bundle():
            self.operation_nodes_offset += self.sandbox_header.sb_ops_count * INDEX_SIZE

        align_delta = self.operation_nodes_offset & 7
        if align_delta != 0:
            self.operation_nodes_offset += 8 - align_delta

        self.base_addr = self.operation_nodes_offset + self.operation_nodes_size

    def _parse_header(self) -> SandboxHeader:
        """
        The header format varies between different iOS versions this is a generic method that unpacks the version
        specific struct and builds a SandboxHeader object to represent the data nicely
        """
        self.data_file.seek(0)
        header_data = self.data_file.read(self.HEADER_STRUCT.size)
        header_vars = self.HEADER_STRUCT.unpack(header_data)
        return self.HEADER_CLS(*header_vars)

    def is_profile_bundle(self) -> bool:
        return self.sandbox_header.profile_type == ProfileType.PROFILE_BUNDLE

    def goto(self, offset: int, relative: bool = False):
        """
        Set the data file offset (a global offset from the beginning of the stream)
        """
        if relative:
            offset = offset * 8 + self.base_addr
        self.data_file.seek(offset)

    def read_short(self, offset: int, relative: bool = False) -> int:
        self.goto(offset, relative)
        return int.from_bytes(self.data_file.read(2), 'little')

    def read_string(self, string_offset: int) -> str:
        """
        Extract string (literal) from given string offset.
        [len][string]
        """
        string_length = self.read_short(string_offset, relative=True) - 1

        # TODO: are the strings really encoded using utf-8..?
        return self.data_file.read(string_length).decode('utf-8')

    def read_binary(self, binary_offset: int) -> tuple[int, ...]:
        binary_length = self.read_short(binary_offset, relative=True)
        return struct.unpack(f'{binary_length}B', self.data_file.read(binary_length))

    def read_op_table(self, op_table_offset: int) -> tuple[int, ...]:
        self.goto(op_table_offset)
        data = self.data_file.read(INDEX_SIZE * self.sandbox_header.sb_ops_count)
        return struct.unpack(f'<{self.sandbox_header.sb_ops_count}H', data)

    def parse_common(self):
        self._parse_regex_list()
        self._parse_global_vars()
        self._parse_policies()
        self._parse_operation_nodes()

    def _parse_regex_list(self) -> None:
        count = self.sandbox_header.regex_count
        if not count:
            logger.info("Sandbox profile does not contain any regexes, skipping  parsing..")
            return

        logger.info(f'Parsing {count} regular expressions at offset {self.regex_table_offset:#x}')

        self.goto(self.regex_table_offset)
        data = self.data_file.read(INDEX_SIZE * count)

        for regex_offset in struct.iter_unpack('<H', data):
            regex_offset, = regex_offset  # Unpack tuple..
            re = self.read_binary(regex_offset)
            logging.debug(f'Current regex relative offset: {regex_offset:#x} len:{len(re)}')
            re_debug_str = "re: [", ", ".join([hex(i) for i in re]), "]"
            logger.debug(re_debug_str)
            self.regex_list.append(sandbox_regex.parse_regex(re))
        logger.debug(self.regex_list)

    def _parse_global_vars(self) -> None:
        count = self.sandbox_header.vars_count
        if not count:
            logger.info("Sandbox profile does not contain any global vars, skipping parsing..")
            return

        logger.info(f"Parsing {count} global vars at offset {self.vars_offset:#x}")

        self.goto(self.vars_offset)
        data = self.data_file.read(INDEX_SIZE * count)
        for var_offset in struct.iter_unpack('<H', data):
            var_offset, = var_offset  # Unpack tuple..
            var_name = self.read_string(var_offset)
            self.global_vars.append(var_name)

        logger.info("global variables are {:s}".format(", ".join(s for s in self.global_vars)))

    def _parse_policies(self) -> None:
        count = self.sandbox_header.entitlements_count
        if not count:
            logger.info("Sandbox profile does not contain any policies (entitlements..?), skipping parsing..")
            return

        # TODO: why is the offset called entitlements but we store them in a member called policies..?
        self.goto(self.entitlements_offset)
        self.policies = struct.unpack(f"<{count}H", self.data_file.read(INDEX_SIZE * count))

    def _parse_operation_nodes(self):
        count = self.sandbox_header.op_nodes_count
        assert count, 'No sandbox operation nodes'
        logger.info(f"Parsing {count} operation nodes at offset:{self.operation_nodes_offset:#x}")

        # Place file pointer to start of operation nodes area.
        self.goto(self.operation_nodes_offset)

        # Read sandbox operations.
        self.operation_nodes = operation_node.build_operation_nodes(self.data_file, count)

        for op_node in self.operation_nodes:
            op_node.convert_filter(sandbox_filter.convert_filter_callback, self.data_file, self, self._keep_builtin_filters)
        logger.info("operation nodes after filter conversion")

    def profiles(self) -> Generator[tuple[int, str], None, None]:
        for i in range(self.sandbox_header.num_profiles):
            profile_offset = self.profiles_offset + self.PROFILE_SIZE * i
            name_offset = self.read_short(profile_offset)
            yield profile_offset, self.read_string(name_offset)

    def print_sandbox_profiles(self) -> None:
        assert (self.is_profile_bundle())
        logger.info(f"Printing {self.sandbox_header.num_profiles} sandbox profiles from bundle")

        for profile_offset, profile_name in self.profiles():
            logger.info(f'Profile name:{profile_name}')

    def decompile(self):
        if self.is_profile_bundle():
            self._decompile_bundle()
        else:
            self._decompile_normal()

    def _decompile_bundle(self):
        logger.info("Input file is a profile bundle.. parsing accordingly")

        # read profiles
        for profile_offset, profile_name in self.profiles():

            # Go past profiles not in list, in case list is defined.
            if self._profiles_to_reverse and profile_name not in self._profiles_to_reverse:
                continue

            logger.info(f"Decompiling profile: {profile_name}")

            # operands to read for each profile
            op_table = self.read_op_table(profile_offset + self.PROFILE_OPS_OFFSET)
            out_fname = os.path.join(self._output_directory, profile_name.replace('/', '_'))
            process_profile(out_fname, self.sb_ops, self.ops_to_reverse, op_table, self.operation_nodes, self._c_output, self._macho)

    def _decompile_normal(self):
        """
        Normal i.e. single profile
        """
        logger.info(f"Input file is not a bundle.. parsing profile at offset {self.profiles_offset:#x}")
        op_table_offset = self.profiles_offset
        op_table = self.read_op_table(op_table_offset)

        # TODO: I dont this this is needed..
        self.goto(self.operation_nodes_offset)
        out_fname = os.path.join(self._output_directory, os.path.splitext(os.path.basename(self.data_file.name))[0])
        process_profile(out_fname, self.sb_ops, self.ops_to_reverse, op_table, self.operation_nodes, self._c_output, self._macho)

    def __repr__(self) -> str:
        return f"""
            header_size: {self._header_size:#x}
            profile_type: {self.sandbox_header.profile_type:#x}
            op_nodes_count: {self.sandbox_header.op_nodes_count:#x}
            sb_ops_count: {self.sandbox_header.sb_ops_count:#x}
            vars_count: {self.sandbox_header.vars_count:#x}
            states_count: {self.sandbox_header.states_count:#x}
            num_profiles: {self.sandbox_header.num_profiles:#x}
            re_table_count: {self.sandbox_header.regex_count:#x}
            entitlements_count: {self.sandbox_header.entitlements_count:#x}

            regex_table_offset: {self.regex_table_offset:#x}
            pattern_vars_offset: {self.vars_offset:#x}
            states_offset: {self.states_offset:#x}
            entitlements_offset: {self.entitlements_offset:#x}
            profiles_offset: {self.profiles_offset:#x}
            profiles_end_offset: {self.profiles_end_offset:#x}
            operation_nodes_offset: {self.operation_nodes_offset:#x}
            operation_nodes_size: {self.operation_nodes_size:#x}
            base_addr: {self.base_addr:#x}
            """


class SandboxData16_5(SandboxData):
    """
    iOS 16.5 sandbox data
    """

    @property
    def HEADER_STRUCT(self) -> struct.Struct:
        return struct.Struct('<HHBBBxHHH')

    @property
    def HEADER_CLS(self) -> Type[SandboxHeader]:
        return SandboxHeader16_5

    @property
    def PROFILE_SIZE(self):
        """
        Should evaluate to 0x17e
        """
        return (self.sandbox_header.sb_ops_count * INDEX_SIZE) + INDEX_SIZE + INDEX_SIZE  # + name + policy index

    @property
    def PROFILE_OPS_OFFSET(self):
        return 4


class SandboxData18_0(SandboxData):

    @property
    def HEADER_STRUCT(self) -> struct.Struct:
        return struct.Struct('<HHBBBxBxHHH')

    @property
    def HEADER_CLS(self) -> Type[SandboxHeader]:
        return SandboxHeader18_0

    @property
    def PROFILE_SIZE(self) -> int:
        # TODO: actually understand what are the new fields to each profile..
        return 0x188

    @property
    def PROFILE_OPS_OFFSET(self) -> int:
        return 8


RELEASES = {
    '16.5': SandboxData16_5,
    '17': SandboxData16_5,
    '18': SandboxData18_0
}


def node_to_c(node):
    queue = [node]
    processed = []

    out = ""
    while len(queue):
        node = queue[0]
        del queue[0]

        out += "node_%x:; // %r\n" % (node.offset, node.raw)
        if node.terminal:
            out += node.c_repr() + "\n\n"
            continue

        out += "if (%s) goto node_%x;\nelse goto node_%x;\n\n" % (node.c_repr(), node.non_terminal.match_offset, node.non_terminal.unmatch_offset)

        if node.non_terminal.match not in processed:
            processed += [node.non_terminal.match]
            queue += [node.non_terminal.match]

        if node.non_terminal.unmatch not in processed:
            processed += [node.non_terminal.unmatch]
            queue += [node.non_terminal.unmatch]

    return out.strip()


def process_profile(outfname, sb_ops, ops_to_reverse, op_table, operation_nodes, c_output, macho):
    if macho:
        c_output = True
    if c_output:
        outfile = open(outfname.strip() + ".c", "wt")
    else:
        out_fname = os.path.join(outfname.strip() + ".sb")
        outfile = open(out_fname, "wt")

    # Extract node for 'default' operation (index 0).
    default_node = operation_node.find_operation_node_by_offset(operation_nodes, op_table[0])
    if not default_node.terminal:
        return

    if c_output:
        outfile.write("extern long allow(const char *);\n")
        outfile.write("extern long deny(const char *);\n")

        outfile.write("extern long unparsed_filter();\n")
        outfile.write("extern long subpath();\n")
        outfile.write("extern long subpath_prefix();\n")

        for f in Filters.filters.values():
            name = f["name"];
            if name == "":
                name = "literal"
            for suffix in ["", "_regex", "_literal", "_prefix"]:
                outfile.write("extern long %s%s();\n" % (name.replace("-", "_"), suffix))
    else:
        outfile.write("(version 1)\n")
        outfile.write("(%s default)\n" % (default_node.terminal))

    # For each operation expand operation node.
    for idx in range(1, len(op_table)):
        offset = op_table[idx]
        operation = sb_ops[idx]
        # Go past operations not in list, in case list is not empty.
        if ops_to_reverse:
            if operation not in ops_to_reverse:
                continue

        node = operation_node.find_operation_node_by_offset(operation_nodes, offset)

        if not node:
            continue

        if c_output:
            outfile.write("long %s()\n{\n" % (operation.replace("-", "_").replace("*", "$"),))
            outfile.write(node_to_c(node))
            outfile.write("\n}\n\n")
            continue

        g = operation_node.build_operation_node_graph(node, default_node)
        if g:
            rg = operation_node.reduce_operation_node_graph(g)
            rg.str_simple_with_metanodes()
            rg.print_vertices_with_operation_metanodes(operation, default_node.terminal.is_allow(), outfile)
        else:
            if node.terminal:
                if node.terminal.type != default_node.terminal.type:
                    outfile.write("(%s %s)\n" % (node.terminal, operation))
                else:
                    modifiers_type = [key for key, val in node.terminal.db_modifiers.items() if len(val)]
                    if modifiers_type:
                        outfile.write("(%s %s)\n" % (node.terminal, operation))

    outfile.close()

    if macho:
        # -O > 0 generates a lot of variable assignments that hinder decompilation readability
        subprocess.run(["clang", outfname.strip() + ".c", "-g", "-O0", "-undefined", "dynamic_lookup", "-Wno-everything", "-o", outfname.strip()])


def main(args: argparse.Namespace, sb_ops: list[str]) -> int:
    sandbox_data = RELEASES[args.release](args, sb_ops)

    # Print the sandbox header to the console
    print(sandbox_data)

    if args.print_sandbox_profiles:
        if sandbox_data.is_profile_bundle():
            sandbox_data.print_sandbox_profiles()
        else:
            logger.error(f"Cannot print sandbox profiles because input file {args.input_file.name} is not a sandbox bundle")
            return 1
        return 0

    ###########################
    # Parse common structures #
    ###########################

    # Regex, global vars, policies, operation_nodes
    sandbox_data.parse_common()

    ##############################
    # Decompile the sandbox data #
    ##############################

    sandbox_data.decompile()


def parse_args() -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(description='Reverse Apple binary sandbox file to SBPL (Sandbox Profile Language) format.')
    parser.add_argument("input_file", type=argparse.FileType('rb'), help="path to the binary sandbox profile")
    parser.add_argument("-r", "--release", help="iOS release version for sandbox profile", choices=RELEASES.keys(), required=True)
    parser.add_argument("-o", "--operations_file", type=argparse.FileType('r'), help="file with list of operations", required=True)
    parser.add_argument("-p", "--profile", dest='profiles_to_reverse', nargs='+', help="profile to reverse (for bundles) (default is to reverse all operations)")
    parser.add_argument("-n", "--operation", dest='ops_to_reverse', nargs='+', help="particular operation(s) to reverse (default is to reverse all operations)")
    # TODO: convert this to pathlib.Path and create directory if it does not already exist..
    parser.add_argument("-d", "--directory", dest='output_directory', help="directory where to write reversed profiles (default is current directory)")
    parser.add_argument("-psb", "--print_sandbox_profiles", action="store_true", help="print sandbox profiles of a given bundle (only for iOS versions 9+)")
    parser.add_argument("-kbf", "--keep_builtin_filters", help="keep builtin filters in output", action="store_true")
    parser.add_argument("-c", "--c_output", help="output a C file rather than Scheme", action="store_true")
    parser.add_argument("-m", "--macho", help="generate a reversible Mach-O file (implies --c_output)", action="store_true")
    parser.set_defaults(output_directory=os.getcwd())

    args = parser.parse_args()
    sb_ops = [l.strip() for l in args.operations_file]
    if not sb_ops:
        parser.error(f'Operations file {args.operations_file.name} is empty!')

    logger.info(f'Read {len(sb_ops)} operations from the operations file')

    # Ensure that all user-request ops to reverse are within the set of sb_ops
    if args.ops_to_reverse and any(op not in sb_ops for op in args.ops_to_reverse):
        parser.error(f'--operation contains an unavailable operation')

    return args, sb_ops


if __name__ == "__main__":
    sys.exit(main(*parse_args()))
