import pytest
from click.testing import CliRunner
import pwnlib

from ffuzzer import libc_check

def test_libc_check():
    # 64 bit test
    elf = pwnlib.elf.elf.ELF('./generic_x64')
    libc_base = 0x7f000000
    assert libc_check(b'0x7f341234', elf, libc_base) == 0x341234
    assert libc_check(b'0x12341234', elf, libc_base) == False
    assert libc_check(b'0xf7341234', elf, libc_base) == False

    # 32 bit test
    elf = pwnlib.elf.elf.ELF('./generic_x32')
    libc_base = 0xf7000000
    assert libc_check(b'0xf7341234', elf, libc_base) == 0x341234
    assert libc_check(b'0x12341234', elf, libc_base) == False
    assert libc_check(b'0x7f341234', elf, libc_base) == False
