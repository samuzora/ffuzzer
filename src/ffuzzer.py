from concurrent.futures import ThreadPoolExecutor
from itertools import repeat

import click
from pwn import *

import util

# --- main ---
@click.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option(
    "-m",
    "--max",
    type=int,
    help="The maximum number of offsets to fuzz.",
    default=100,
    show_default=True,
)
@click.option(
    "-c",
    "--custom",
    type=str,
    help="Look for a custom string in the %p leak. If you want to fuzz an ASCII string, please convert it to hexadecimal first.",
)
@click.option(
    "-r",
    "--remote",
    type=(str, int),
    help="Fuzz on remote instead of locally. Input format: -r HOST PORT"
)
@click.option(
    "-t",
    "--num-threads",
    type=int,
    help="Number of threads to use.",
    default=8,
    show_default=True
)
def cli(binary, max, custom, remote, num_threads):
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
    offset = []
    canaries = []
    pies = {}
    custom_strings = {}
    elf = context.binary = ELF(binary)
    context.log_level = "error"

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

        route_data = {
            "route": route,
            "fmt_index": fmt_index,
            "keyword": keyword
        }
        other_data = {
            "binary": binary,
            "progress": progress,
            "max": max,
            "custom": custom,
            "remote": remote
        }
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            current_progress = 0
            for result in executor.map(fuzz, range(1, max), repeat(route_data), repeat(other_data)):
                current_progress += 1
                with context.local(log_level="info"):
                    progress.status(f"{(current_progress)/(max-1) * 100}%")

                match result["type"]:
                    case "offset":
                        click.secho("Offset found", fg="blue")
                        offset.append(result["index"])
                    case "pie":
                        symbol = result["symbol"]
                        click.secho(f"Possible PIE leak of {symbol} found", fg="cyan")
                        if pies.get(symbol):
                            pies[symbol].append(result["index"])
                        else:
                            pies[symbol] = [result["index"]]
                    case "canary":
                        click.secho("Possible canary found", fg="yellow")
                        canaries.append(result["index"])
                    case "custom":
                        click.secho(f"Custom string found in {result['leak'].decode()}", fg="magenta")
                        if custom_strings.get(custom):
                            custom_strings[result['leak'].decode()].append(result["index"])
                        else:
                            custom_strings[result['leak'].decode()] = [result["index"]]
                

    except:
        pass
    util.summary(progress, offset, canaries, pies, custom_strings)

def fuzz(i, route_data, other_data):
    elf = context.binary = ELF(other_data["binary"])
    context.log_level = "error"

    if other_data["remote"] is None:
        p = process(stdin=PTY, stdout=PTY)
    else:
        p = connect(other_data["remote"][0], other_data["remote"][1])

    index = -1
    for step in route_data["route"]:
        index += 1
        if b"S%pF" in step:
            util.send_payload(i, step, p)
        else:
            p.sendline(step)
        if index == route_data["fmt_index"]:
            # scan leak
            leak_type = util.identify_leak(
                i,
                p,
                route_data["keyword"],
                elf,
                other_data["custom"],
            )
            return leak_type

    p.close()
