import pytest
from click.testing import CliRunner
import pwnlib

from ffuzzer import offset_check

def test_offset_check():
    assert offset_check(b'0x70243525', 5) == True
    assert offset_check(b'0x12345678', 10) == False
