import pytest
from click.testing import CliRunner
import pwnlib

from ffuzzer import pie_check

def test_canary_check():
    elf = pwnlib.elf.elf.ELF('./pie_x64')
    assert pie_check(b'0x555555400a99', elf) in elf.sym
    assert pie_check(b'0x12341234', elf) == False
    assert pie_check(b'0x1234123412341200', elf) == False
