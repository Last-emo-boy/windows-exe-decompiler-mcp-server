"""ELF and Mach-O binary parser using Python's built-in struct module."""

import json
import struct
import os

MAX_ENTRIES = 2000

# ── ELF constants ──────────────────────────────────────────────────────────

ELF_MAGIC = b"\x7fELF"

ELF_CLASS = {1: 32, 2: 64}
ELF_DATA = {1: "little", 2: "big"}
ELF_MACHINE = {
    0: "EM_NONE", 2: "EM_SPARC", 3: "EM_386", 6: "EM_486", 7: "EM_860",
    8: "EM_MIPS", 20: "EM_PPC", 21: "EM_PPC64", 40: "EM_ARM",
    42: "EM_SH", 43: "EM_SPARCV9", 50: "EM_IA_64", 62: "EM_X86_64",
    183: "EM_AARCH64", 243: "EM_RISCV",
}

SHT_NAMES = {
    0: "SHT_NULL", 1: "SHT_PROGBITS", 2: "SHT_SYMTAB", 3: "SHT_STRTAB",
    4: "SHT_RELA", 5: "SHT_HASH", 6: "SHT_DYNAMIC", 7: "SHT_NOTE",
    8: "SHT_NOBITS", 9: "SHT_REL", 10: "SHT_SHLIB", 11: "SHT_DYNSYM",
    14: "SHT_INIT_ARRAY", 15: "SHT_FINI_ARRAY",
}

PT_NAMES = {
    0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP",
    4: "PT_NOTE", 5: "PT_SHLIB", 6: "PT_PHDR", 7: "PT_TLS",
    0x6474e550: "PT_GNU_EH_FRAME", 0x6474e551: "PT_GNU_STACK",
    0x6474e552: "PT_GNU_RELRO", 0x6474e553: "PT_GNU_PROPERTY",
}

DT_NAMES = {
    0: "DT_NULL", 1: "DT_NEEDED", 2: "DT_PLTRELSZ", 3: "DT_PLTGOT",
    4: "DT_HASH", 5: "DT_STRTAB", 6: "DT_SYMTAB", 7: "DT_RELA",
    8: "DT_RELASZ", 10: "DT_STRSZ", 11: "DT_SYMENT", 12: "DT_INIT",
    13: "DT_FINI", 14: "DT_SONAME", 15: "DT_RPATH", 17: "DT_REL",
    20: "DT_PLTREL", 21: "DT_DEBUG", 23: "DT_JMPREL",
    25: "DT_INIT_ARRAY", 26: "DT_FINI_ARRAY", 28: "DT_RUNPATH",
    30: "DT_FLAGS", 0x6ffffffb: "DT_FLAGS_1",
    0x6ffffffe: "DT_VERNEED", 0x6fffffff: "DT_VERNEEDNUM",
    0x6ffffff0: "DT_VERSYM",
}

STB_NAMES = {0: "STB_LOCAL", 1: "STB_GLOBAL", 2: "STB_WEAK"}
STT_NAMES = {
    0: "STT_NOTYPE", 1: "STT_OBJECT", 2: "STT_FUNC",
    3: "STT_SECTION", 4: "STT_FILE", 10: "STT_LOOS", 13: "STT_HIOS",
}

# ── Mach-O constants ──────────────────────────────────────────────────────

MH_MAGIC_32 = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_32 = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

MH_FILETYPE = {
    1: "MH_OBJECT", 2: "MH_EXECUTE", 3: "MH_FVMLIB", 4: "MH_CORE",
    5: "MH_PRELOAD", 6: "MH_DYLIB", 7: "MH_DYLINKER", 8: "MH_BUNDLE",
    9: "MH_DYLIB_STUB", 10: "MH_DSYM", 11: "MH_KEXT_BUNDLE",
}

CPU_TYPE = {
    1: "VAX", 6: "MC680x0", 7: "x86", 0x01000007: "x86_64",
    10: "MC98000", 11: "HPPA", 12: "ARM", 0x0100000C: "ARM64",
    13: "MC88000", 14: "SPARC", 15: "i860", 18: "PowerPC",
    0x01000012: "PowerPC64",
}

LC_NAMES = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0x3: "LC_SYMSEG",
    0x4: "LC_THREAD", 0x5: "LC_UNIXTHREAD", 0x6: "LC_LOADFVMLIB",
    0xB: "LC_DYSYMTAB", 0xC: "LC_LOAD_DYLIB", 0xD: "LC_ID_DYLIB",
    0xE: "LC_LOAD_DYLINKER", 0xF: "LC_ID_DYLINKER",
    0x19: "LC_SEGMENT_64", 0x1A: "LC_ROUTINES_64",
    0x1D: "LC_UUID", 0x1F: "LC_CODE_SIGNATURE",
    0x22: "LC_DYLD_INFO", 0x24: "LC_VERSION_MIN_MACOSX",
    0x25: "LC_VERSION_MIN_IPHONEOS", 0x26: "LC_FUNCTION_STARTS",
    0x29: "LC_DATA_IN_CODE", 0x2A: "LC_SOURCE_VERSION",
    0x32: "LC_BUILD_VERSION",
    0x80000022: "LC_DYLD_INFO_ONLY", 0x80000018: "LC_DYLD_ENVIRONMENT",
    0x80000028: "LC_MAIN", 0x8000001C: "LC_RPATH",
    0x8000002B: "LC_DYLD_EXPORTS_TRIE", 0x8000002C: "LC_DYLD_CHAINED_FIXUPS",
}


# ── Helpers ────────────────────────────────────────────────────────────────

def _read_bytes(data, offset, size):
    """Safe slice that raises on truncation."""
    end = offset + size
    if end > len(data):
        raise ValueError(f"Truncated: need {end} bytes, have {len(data)}")
    return data[offset:end]


def _read_cstring(data, offset, max_len=256):
    """Read a null-terminated string from data."""
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, offset + max_len)
    if end == -1:
        end = min(offset + max_len, len(data))
    try:
        return data[offset:end].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _strtab_string(data, strtab_offset, strtab_size, str_index):
    """Read string from ELF string table."""
    pos = strtab_offset + str_index
    if pos < 0 or pos >= len(data) or str_index >= strtab_size:
        return ""
    return _read_cstring(data, pos)


# ── ELF parser ─────────────────────────────────────────────────────────────

def parse_elf(path):
    try:
        if not os.path.isfile(path):
            return {"ok": False, "error": f"File not found: {path}"}

        with open(path, "rb") as f:
            data = f.read()

        if len(data) < 64:
            return {"ok": False, "error": "File too small to be a valid ELF"}

        if data[:4] != ELF_MAGIC:
            return {"ok": False, "error": "Not an ELF file (bad magic)"}

        ei_class = data[4]
        ei_data = data[5]

        bits = ELF_CLASS.get(ei_class)
        if bits is None:
            return {"ok": False, "error": f"Unknown ELF class: {ei_class}"}

        endian = ELF_DATA.get(ei_data)
        if endian is None:
            return {"ok": False, "error": f"Unknown ELF data encoding: {ei_data}"}

        e = "<" if endian == "little" else ">"
        is64 = bits == 64

        # ELF header
        if is64:
            if len(data) < 64:
                return {"ok": False, "error": "Truncated ELF64 header"}
            hdr = struct.unpack_from(f"{e}HHI QQQ I HHHHHH", data, 16)
        else:
            if len(data) < 52:
                return {"ok": False, "error": "Truncated ELF32 header"}
            hdr = struct.unpack_from(f"{e}HHI III I HHHHHH", data, 16)

        e_type, e_machine_val, e_version, e_entry, e_phoff, e_shoff, \
            e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, \
            e_shnum, e_shstrndx = hdr

        machine = ELF_MACHINE.get(e_machine_val, f"0x{e_machine_val:x}")

        # ── Sections ───────────────────────────────────────────────────
        sections = []
        shstrtab_off = 0
        shstrtab_sz = 0

        if e_shoff and e_shnum and e_shentsize:
            # Read shstrtab first
            if is64:
                sh_fmt = f"{e}I I Q Q Q Q I I Q Q"
                sh_size = 64
            else:
                sh_fmt = f"{e}I I I I I I I I I I"
                sh_size = 40

            if e_shstrndx < e_shnum:
                str_sh_off = e_shoff + e_shstrndx * e_shentsize
                if str_sh_off + sh_size <= len(data):
                    sh_fields = struct.unpack_from(sh_fmt, data, str_sh_off)
                    shstrtab_off = sh_fields[4]
                    shstrtab_sz = sh_fields[5]

            count = min(e_shnum, MAX_ENTRIES)
            for i in range(count):
                off = e_shoff + i * e_shentsize
                if off + sh_size > len(data):
                    break
                sh = struct.unpack_from(sh_fmt, data, off)
                sh_name_idx = sh[0]
                sh_type_val = sh[1]
                sh_flags_val = sh[2]
                sh_addr = sh[3]
                sh_offset = sh[4]  # noqa: F841
                sh_sz = sh[5]

                name = _strtab_string(data, shstrtab_off, shstrtab_sz, sh_name_idx)
                sections.append({
                    "name": name,
                    "type": SHT_NAMES.get(sh_type_val, f"0x{sh_type_val:x}"),
                    "addr": sh_addr,
                    "size": sh_sz,
                    "flags": sh_flags_val,
                })

        # ── Segments ───────────────────────────────────────────────────
        segments = []
        if e_phoff and e_phnum and e_phentsize:
            count = min(e_phnum, MAX_ENTRIES)
            for i in range(count):
                off = e_phoff + i * e_phentsize
                if is64:
                    if off + 56 > len(data):
                        break
                    p = struct.unpack_from(f"{e}I I Q Q Q Q Q Q", data, off)
                    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = p
                else:
                    if off + 32 > len(data):
                        break
                    p = struct.unpack_from(f"{e}I I I I I I I I", data, off)
                    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = p

                segments.append({
                    "type": PT_NAMES.get(p_type, f"0x{p_type:x}"),
                    "vaddr": p_vaddr,
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                    "flags": p_flags,
                })

        # ── Symbols ────────────────────────────────────────────────────
        symbols = _parse_elf_symbols(data, sections, e, is64, shstrtab_off, shstrtab_sz, e_shoff, e_shnum, e_shentsize)

        # ── Dynamic entries ────────────────────────────────────────────
        dynamic = _parse_elf_dynamic(data, sections, e, is64, e_shoff, e_shnum, e_shentsize)

        return {
            "ok": True,
            "format": "ELF",
            "class": bits,
            "endian": endian,
            "machine": machine,
            "entry_point": e_entry,
            "sections": sections,
            "segments": segments,
            "symbols": symbols,
            "dynamic": dynamic,
        }

    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _find_section_by_type(sections_raw, target_type):
    """Return (offset, size, link) for first section of given type, from raw headers."""
    for s in sections_raw:
        if s["type_val"] == target_type:
            return s
    return None


def _parse_elf_section_headers_raw(data, e, is64, e_shoff, e_shnum, e_shentsize):
    """Parse raw section headers for internal use."""
    if is64:
        sh_fmt = f"{e}I I Q Q Q Q I I Q Q"
    else:
        sh_fmt = f"{e}I I I I I I I I I I"
    sh_size = struct.calcsize(sh_fmt)
    result = []
    count = min(e_shnum, MAX_ENTRIES)
    for i in range(count):
        off = e_shoff + i * e_shentsize
        if off + sh_size > len(data):
            break
        sh = struct.unpack_from(sh_fmt, data, off)
        result.append({
            "name_idx": sh[0],
            "type_val": sh[1],
            "flags": sh[2],
            "addr": sh[3],
            "offset": sh[4],
            "size": sh[5],
            "link": sh[6],
            "info": sh[7],
        })
    return result


def _parse_elf_symbols(data, sections, e, is64, shstrtab_off, shstrtab_sz, e_shoff, e_shnum, e_shentsize):
    """Parse symbol tables (.symtab and .dynsym)."""
    symbols = []
    if not e_shoff or not e_shnum or not e_shentsize:
        return symbols

    raw_sections = _parse_elf_section_headers_raw(data, e, is64, e_shoff, e_shnum, e_shentsize)

    for sh in raw_sections:
        if sh["type_val"] not in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM
            continue

        sym_off = sh["offset"]
        sym_sz = sh["size"]
        link = sh["link"]

        # Get the linked string table
        str_off = 0
        str_sz = 0
        if 0 <= link < len(raw_sections):
            str_sec = raw_sections[link]
            str_off = str_sec["offset"]
            str_sz = str_sec["size"]

        if is64:
            ent_fmt = f"{e}I B B H Q Q"
            ent_size = 24
        else:
            ent_fmt = f"{e}I I I B B H"
            ent_size = 16

        count = sym_sz // ent_size if ent_size else 0
        count = min(count, MAX_ENTRIES - len(symbols))

        for j in range(count):
            pos = sym_off + j * ent_size
            if pos + ent_size > len(data):
                break

            fields = struct.unpack_from(ent_fmt, data, pos)
            if is64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = fields
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = fields

            bind_val = (st_info >> 4) & 0xF
            type_val = st_info & 0xF

            name = _strtab_string(data, str_off, str_sz, st_name)
            if not name:
                continue

            symbols.append({
                "name": name,
                "value": st_value,
                "type": STT_NAMES.get(type_val, f"0x{type_val:x}"),
                "bind": STB_NAMES.get(bind_val, f"0x{bind_val:x}"),
            })

        if len(symbols) >= MAX_ENTRIES:
            break

    return symbols


def _parse_elf_dynamic(data, sections, e, is64, e_shoff, e_shnum, e_shentsize):
    """Parse .dynamic section entries, resolving DT_NEEDED strings."""
    dynamic = []
    if not e_shoff or not e_shnum or not e_shentsize:
        return dynamic

    raw_sections = _parse_elf_section_headers_raw(data, e, is64, e_shoff, e_shnum, e_shentsize)

    for sh in raw_sections:
        if sh["type_val"] != 6:  # SHT_DYNAMIC
            continue

        dyn_off = sh["offset"]
        dyn_sz = sh["size"]
        link = sh["link"]

        # Linked strtab for resolving DT_NEEDED etc.
        dyn_str_off = 0
        dyn_str_sz = 0
        if 0 <= link < len(raw_sections):
            dyn_str = raw_sections[link]
            dyn_str_off = dyn_str["offset"]
            dyn_str_sz = dyn_str["size"]

        if is64:
            ent_fmt = f"{e}qQ"
            ent_size = 16
        else:
            ent_fmt = f"{e}iI"
            ent_size = 8

        count = dyn_sz // ent_size if ent_size else 0
        count = min(count, MAX_ENTRIES)

        for j in range(count):
            pos = dyn_off + j * ent_size
            if pos + ent_size > len(data):
                break
            d_tag, d_val = struct.unpack_from(ent_fmt, data, pos)

            tag_name = DT_NAMES.get(d_tag, f"0x{d_tag:x}")

            # Resolve string values for DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH
            if d_tag in (1, 14, 15, 29) and dyn_str_off:
                val = _strtab_string(data, dyn_str_off, dyn_str_sz, d_val)
            else:
                val = d_val

            dynamic.append({"tag": tag_name, "value": val})

            if d_tag == 0:  # DT_NULL
                break

        break  # Only one .dynamic section expected

    return dynamic


# ── Mach-O parser ──────────────────────────────────────────────────────────

def parse_macho(path):
    try:
        if not os.path.isfile(path):
            return {"ok": False, "error": f"File not found: {path}"}

        with open(path, "rb") as f:
            data = f.read()

        if len(data) < 4:
            return {"ok": False, "error": "File too small"}

        magic = struct.unpack_from("<I", data, 0)[0]

        is_fat = magic in (FAT_MAGIC, FAT_CIGAM)
        if is_fat:
            return _parse_fat_macho(data, magic)

        return _parse_single_macho(data, 0)

    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _parse_fat_macho(data, magic):
    """Parse a fat/universal Mach-O binary."""
    swap = (magic == FAT_CIGAM)
    e = ">" if not swap else "<"

    if len(data) < 8:
        return {"ok": False, "error": "Truncated fat header"}

    nfat_arch = struct.unpack_from(f"{e}I", data, 4)[0]
    if nfat_arch > 20:
        return {"ok": False, "error": f"Suspicious nfat_arch: {nfat_arch}"}

    architectures = []
    first_offset = None

    for i in range(nfat_arch):
        off = 8 + i * 20
        if off + 20 > len(data):
            break
        cpu, cpusub, arch_off, arch_size, arch_align = struct.unpack_from(f"{e}iiIII", data, off)
        architectures.append({
            "cputype": CPU_TYPE.get(cpu, f"0x{cpu:x}"),
            "cpusubtype": cpusub,
            "offset": arch_off,
            "size": arch_size,
        })
        if first_offset is None:
            first_offset = arch_off

    # Parse the first slice
    result = {"ok": False, "error": "No architectures in fat binary"}
    if first_offset is not None:
        result = _parse_single_macho(data, first_offset)

    result["is_fat"] = True
    result["fat_architectures"] = architectures
    return result


def _parse_single_macho(data, base_offset):
    """Parse a single Mach-O image starting at base_offset."""
    if base_offset + 4 > len(data):
        return {"ok": False, "error": "Truncated Mach-O at offset"}

    magic = struct.unpack_from("<I", data, base_offset)[0]

    if magic == MH_MAGIC_64:
        is64 = True
        e = "<"
    elif magic == MH_CIGAM_64:
        is64 = True
        e = ">"
    elif magic == MH_MAGIC_32:
        is64 = False
        e = "<"
    elif magic == MH_CIGAM_32:
        is64 = False
        e = ">"
    else:
        return {"ok": False, "error": f"Bad Mach-O magic: 0x{magic:08x}"}

    hdr_size = 32 if is64 else 28
    if base_offset + hdr_size > len(data):
        return {"ok": False, "error": "Truncated Mach-O header"}

    if is64:
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = \
            struct.unpack_from(f"{e}iiIIIII", data, base_offset + 4)
    else:
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = \
            struct.unpack_from(f"{e}iiIIII", data, base_offset + 4)

    load_commands = []
    sections = []
    symbols = []

    cmd_offset = base_offset + hdr_size
    symtab_info = None

    ncmds = min(ncmds, MAX_ENTRIES)

    for _ in range(ncmds):
        if cmd_offset + 8 > len(data):
            break

        cmd, cmdsize = struct.unpack_from(f"{e}II", data, cmd_offset)
        if cmdsize < 8:
            break

        cmd_name = LC_NAMES.get(cmd & 0x7FFFFFFF, LC_NAMES.get(cmd, f"0x{cmd:x}"))
        lc_entry = {"cmd": cmd_name, "cmdsize": cmdsize}

        # LC_SEGMENT / LC_SEGMENT_64
        if cmd in (0x1, 0x19):
            secs = _parse_macho_segment(data, cmd_offset, e, is64, cmd)
            lc_entry["data"] = {"sections": len(secs)}
            sections.extend(secs[:MAX_ENTRIES - len(sections)])

        # LC_SYMTAB
        elif cmd == 0x2:
            if cmd_offset + 24 <= len(data):
                symoff, nsyms, stroff, strsize = struct.unpack_from(
                    f"{e}IIII", data, cmd_offset + 8)
                symtab_info = {
                    "symoff": base_offset + symoff,
                    "nsyms": nsyms,
                    "stroff": base_offset + stroff,
                    "strsize": strsize,
                }
                lc_entry["data"] = {"nsyms": nsyms, "strsize": strsize}

        # LC_LOAD_DYLIB, LC_ID_DYLIB, LC_RPATH
        elif cmd in (0xC, 0xD, 0x8000001C):
            if cmd_offset + 12 <= len(data):
                str_off_in_cmd = struct.unpack_from(f"{e}I", data, cmd_offset + 8)[0]
                name = _read_cstring(data, cmd_offset + str_off_in_cmd, cmdsize - str_off_in_cmd)
                lc_entry["data"] = {"name": name}

        # LC_UUID
        elif cmd == 0x1D:
            if cmd_offset + 24 <= len(data):
                uuid_bytes = data[cmd_offset + 8:cmd_offset + 24]
                lc_entry["data"] = {"uuid": uuid_bytes.hex()}

        # LC_MAIN
        elif cmd == 0x80000028:
            if cmd_offset + 24 <= len(data):
                entryoff, stacksize = struct.unpack_from(f"{e}QQ", data, cmd_offset + 8)
                lc_entry["data"] = {"entryoff": entryoff, "stacksize": stacksize}

        # LC_BUILD_VERSION
        elif cmd == 0x32:
            if cmd_offset + 24 <= len(data):
                platform, minos, sdk, ntools = struct.unpack_from(
                    f"{e}IIII", data, cmd_offset + 8)
                lc_entry["data"] = {"platform": platform, "minos": minos, "sdk": sdk}

        else:
            lc_entry["data"] = {}

        load_commands.append(lc_entry)
        cmd_offset += cmdsize

    # Parse symbols from LC_SYMTAB
    if symtab_info:
        symbols = _parse_macho_symbols(data, symtab_info, e, is64)

    return {
        "ok": True,
        "format": "MachO",
        "cputype": CPU_TYPE.get(cputype, f"0x{cputype:x}"),
        "cpusubtype": cpusubtype,
        "filetype": MH_FILETYPE.get(filetype, f"0x{filetype:x}"),
        "load_commands": load_commands,
        "sections": sections,
        "symbols": symbols,
        "is_fat": False,
    }


def _parse_macho_segment(data, cmd_offset, e, is64, cmd):
    """Parse sections from an LC_SEGMENT or LC_SEGMENT_64."""
    sections = []
    if is64:
        if cmd_offset + 72 > len(data):
            return sections
        segname_raw = data[cmd_offset + 8:cmd_offset + 24]
        nsects = struct.unpack_from(f"{e}I", data, cmd_offset + 64)[0]
        sec_offset = cmd_offset + 72
        sec_size = 80
    else:
        if cmd_offset + 56 > len(data):
            return sections
        segname_raw = data[cmd_offset + 8:cmd_offset + 24]
        nsects = struct.unpack_from(f"{e}I", data, cmd_offset + 48)[0]
        sec_offset = cmd_offset + 56
        sec_size = 68

    segname = segname_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    nsects = min(nsects, MAX_ENTRIES)

    for i in range(nsects):
        s_off = sec_offset + i * sec_size
        if s_off + sec_size > len(data):
            break

        sectname_raw = data[s_off:s_off + 16]
        seg_raw = data[s_off + 16:s_off + 32]
        sectname = sectname_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        seg = seg_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

        if is64:
            addr, size = struct.unpack_from(f"{e}QQ", data, s_off + 32)
        else:
            addr, size = struct.unpack_from(f"{e}II", data, s_off + 32)

        sections.append({
            "sectname": sectname,
            "segname": seg,
            "addr": addr,
            "size": size,
        })

    return sections


def _parse_macho_symbols(data, info, e, is64):
    """Parse Mach-O symbol table (nlist entries)."""
    symbols = []
    symoff = info["symoff"]
    nsyms = min(info["nsyms"], MAX_ENTRIES)
    stroff = info["stroff"]
    strsize = info["strsize"]

    if is64:
        nlist_fmt = f"{e}I B B H Q"
        nlist_size = 16
    else:
        nlist_fmt = f"{e}I B b H I"
        nlist_size = 12

    for i in range(nsyms):
        pos = symoff + i * nlist_size
        if pos + nlist_size > len(data):
            break

        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(nlist_fmt, data, pos)

        name = _strtab_string(data, stroff, strsize, n_strx)
        if not name:
            continue

        # Classify type
        if n_type & 0x0E == 0x0E:
            type_str = "indirect"
        elif n_type & 0x0E == 0x0A:
            type_str = "prebound_undef"
        elif n_type & 0x0E == 0x0C:
            type_str = "pbud"
        elif n_type & 0x0E == 0x02:
            type_str = "absolute"
        elif n_type & 0x0E == 0x00:
            if n_type & 0x01:
                type_str = "external"
            else:
                type_str = "local" if n_sect else "undef"
        else:
            type_str = f"0x{n_type:02x}"

        symbols.append({
            "name": name,
            "value": n_value,
            "type": type_str,
        })

    return symbols


# ── Format detection ───────────────────────────────────────────────────────

def detect_format(path):
    try:
        if not os.path.isfile(path):
            return {"ok": False, "error": f"File not found: {path}"}

        with open(path, "rb") as f:
            header = f.read(4)

        if len(header) < 4:
            return {"ok": True, "format": "unknown"}

        if header[:2] == b"MZ":
            return {"ok": True, "format": "PE"}

        if header == ELF_MAGIC:
            return {"ok": True, "format": "ELF"}

        magic32 = struct.unpack("<I", header)[0]

        if magic32 in (MH_MAGIC_32, MH_MAGIC_64, MH_CIGAM_32, MH_CIGAM_64):
            return {"ok": True, "format": "MachO"}

        if magic32 in (FAT_MAGIC, FAT_CIGAM):
            return {"ok": True, "format": "FatMachO"}

        return {"ok": True, "format": "unknown"}

    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    raw = sys.stdin.read()
    request = json.loads(raw)
    action = request.get("action", "detect_format")
    file_path = request.get("file_path", "")

    if action == "detect_format":
        result = detect_format(file_path)
    elif action == "parse_elf":
        result = parse_elf(file_path)
    elif action == "parse_macho":
        result = parse_macho(file_path)
    else:
        result = {"ok": False, "error": f"Unknown action: {action}"}

    print(json.dumps(result))
