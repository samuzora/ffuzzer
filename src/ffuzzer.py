import click
from pwn import *

import checkers
import util

# --- main ---
@click.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option(
    "-m",
    "--max",
    type=int,
    help="The maximum number of offsets to fuzz.",
    default=200,
    show_default=True,
)
@click.option(
    "-w",
    "--write",
    type=str,
    help="The name of the function you wish to overwrite something with in the GOT. Enables partial RELRO mode.",
    default=None,
)
@click.option(
    "-c",
    "--custom",
    type=str,
    help="Look for a custom string in the %p leak. If you want to fuzz an ASCII string, please convert it to hexadecimal first.",
)
def cli(binary, max, write, custom):
    """Automatic format string fuzzer by samuzora.

    Currently, this fuzzer can fuzz:

        1. Input offset

        2. Canary leaks

        3. PIE leaks

        4. Custom strings

    On loading the binary, the fuzzer needs you to tell it how to get to the format string vuln.
    Input S%pF where you'd expect the format string leak to be.
    When the program detects a leak, fuzzing will start automatically.

    You can CTRL+C anytime during the fuzzing, the fuzzer will output the summary of the leaks."""

    # --- setup ---
    max += 1
    elf = context.binary = ELF(binary)
    context.log_level = "error"
    offset = []
    canaries = []
    pies = {}
    custom_strings = {}

    # --- main ---
    with context.local(log_level="info"):
        progress = log.progress("Obtaining route to format string leak...")
        progress.status(
            "Please lead the program to the format string leak, and input S%pF where you'd expect the leak to be."
        )

    route, fmt_index, keyword = util.get_route()

    with context.local(log_level="info"):
        progress.status("Done!")

    try:
        with context.local(log_level="info"):
            progress = log.progress("Fuzzing format strings...")

        for i in range(1, max):
            with context.local(log_level="info"):
                progress.status(f"{(i-1)/(max-1) * 100}%")
            p = process(stdin=PTY, stdout=PTY)
            index = -1
            for step in route:
                index += 1
                if b"S%pF" in step:
                    util.send_payload(i, step, p)
                else:
                    p.sendline(step)
                if index == fmt_index:
                    if write is None:
                        # scan leak
                        leak_type = util.identify_leak(
                            i,
                            p,
                            keyword,
                            elf,
                            custom,
                        )

                        match leak_type["type"]:
                            case "offset":
                                click.secho("Offset found", fg="blue")
                                offset.append(i)
                            case "pie":
                                symbol = leak_type["symbol"]
                                click.secho(f"Possible PIE leak of {symbol} found", fg="cyan")
                                if pies.get(symbol):
                                    pies[symbol].append(i)
                                else:
                                    pies[symbol] = [i]
                            case "canary":
                                click.secho("Possible canary found", fg="yellow")
                                canaries.append(i)
                            case "custom":
                                click.secho(f"Custom string found in {leak.decode()}", fg="magenta")
                                if custom_strings.get(custom):
                                    custom_strings[leak.decode()].append(i)
                                else:
                                    custom_strings[leak.decode()] = [i]

                    else:
                        # we are in partial RELRO mode, just fuzz offset

                        # recv until start of leak
                        p.recvuntil(keyword[0])
                        if keyword[1] != b"":
                            # end of leak is not empty
                            leak = p.recvuntil(keyword[1], drop=True).strip()
                        else:
                            # end of leak is empty, just receive the rest of the input
                            leak = p.clean().strip()

                        # process leak
                        if checkers.offset_check(leak, i):
                            click.secho("Offset found", fg="blue")
                            offset.append(i)
                            util.print_got(elf, write, i)
                            raise click.Abort
            p.close()
    except click.Abort:
        pass
    util.summary(progress, offset, canaries, pies, custom_strings)
