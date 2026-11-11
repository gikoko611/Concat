#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Jareer Abdullah
"""Fails when any 64-bit native library in an APK is not aligned for 16 KB pages.

A phone whose kernel uses 16 KB pages - Android 15 and later can, and
Google Play requires every app to support it - refuses to load a library
whose LOAD segments are aligned to less. v0.2.8 shipped
libconcat_android.so at 4 KB beside three 16 KB libraries.

32-bit Android libraries are skipped: the 16 KB page-size compatibility
check is for 64-bit ELF libraries. This keeps ARMv7 APKs buildable.

    scripts/ci/check-16k-pages.py path/to/app.apk
"""
import struct
import sys
import zipfile

PAGE = 16384


def load_alignment(elf: bytes) -> int:
    if elf[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if elf[4] == 1:  # ELF32
        phoff = struct.unpack_from("<I", elf, 0x1C)[0]
        phentsize, phnum = struct.unpack_from("<HH", elf, 0x2A)
        align_offset = 0x1C
        align_format = "<I"
    elif elf[4] == 2:  # ELF64
        phoff = struct.unpack_from("<Q", elf, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", elf, 0x36)
        align_offset = 0x30
        align_format = "<Q"
    else:
        raise ValueError("unsupported ELF class")
    aligns = [
        struct.unpack_from(align_format, elf, phoff + i * phentsize + align_offset)[0]
        for i in range(phnum)
        if struct.unpack_from("<I", elf, phoff + i * phentsize)[0] == 1
    ]
    return min(aligns) if aligns else 0


def main() -> int:
    bad = 0
    with zipfile.ZipFile(sys.argv[1]) as apk:
        for name in apk.namelist():
            if not (name.startswith("lib/") and name.endswith(".so")):
                continue
            elf = apk.read(name)
            if len(elf) > 5 and elf[:4] == b"\x7fELF" and elf[4] == 1:
                print(f"skip  32-bit  {name} (16 KB check is for 64-bit ELF)")
                continue
            align = load_alignment(elf)
            ok = align >= PAGE
            bad += not ok
            print(f"{'ok ' if ok else 'BAD'} {align:>6}  {name}")
    if bad:
        print(f"{bad} librar{'y is' if bad == 1 else 'ies are'} not aligned for 16 KB pages")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
