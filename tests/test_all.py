import pytest
from click.testing import CliRunner
import pwnlib

from ffuzzer import cli

def test_all():
    runner = CliRunner()
    result = runner.invoke(cli, ['-m 50', './generic_x64'], input='1\nS%pF\n')
    assert result.exit_code == 0
