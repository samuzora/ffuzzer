import pytest
from click.testing import CliRunner
import pwnlib

from ffuzzer import cli

def test_all():
    runner = CliRunner()
    result = runner.invoke(cli, ['-x 50', './generic_x64'], input='1\nST%1$pEN\n')
    assert result.exit_code == 0
