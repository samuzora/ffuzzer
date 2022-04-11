import pytest
from click.testing import CliRunner
import pwnlib

from ffuzzer import canary_check

def test_canary_check():
    # 64-bit check
    elf = pwnlib.elf.elf.ELF('./generic_x64')
    assert canary_check(b'0x1234123412341200', elf) == True
    assert canary_check(b'0x1234123412341234', elf) == False
    assert canary_check(b'0x12341200', elf) == False

    # 32-bit check
    elf = pwnlib.elf.elf.ELF('./generic_x32')
    assert canary_check(b'0x12341200', elf) == True
    assert canary_check(b'0x12341234', elf) == False
    assert canary_check(b'0x1234123412341200', elf) == False
