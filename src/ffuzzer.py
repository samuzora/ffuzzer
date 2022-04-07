import regex
import click
import time

from pwn import *

# --- main ---
@click.command()
@click.option('-x', '--max', type=int, help='The maximum number of offsets to fuzz. Defaults to 200.', default=200)
@click.argument('binary')
def cli(binary, max):
    """Automatic format string fuzzer by samuzora. 

Currently, this fuzzer can fuzz:

    1. Input offset

    2. Canary leaks

    3. PIE leaks

    4. LIBC base (ASLR) leaks

On loading the binary, the fuzzer needs you to tell it how to get to the format string vuln. 
Input ST%1$pEN where you'd expect the format string leak to be.
When the program detects a leak, fuzzing will start automatically.

You can CTRL+C anytime during the fuzzing, the fuzzer will output the summary of the leaks."""


    # --- setup ---
    max += 1
    elf = context.binary = ELF(binary)
    libc = elf.libc
    context.log_level = 'error'
    offset = []
    canaries = []
    pies = {}
    libcs = {}

    # --- main ---
    with context.local(log_level='info'):
        progress = log.progress('Obtaining route to format string leak...')
        progress.status("Please lead the program to the format string leak, and input ST%1$pEN where you'd expect the leak to be.")

    route, fmt_index, keyword = get_route()

    with context.local(log_level='info'):
        progress.status("Done!")

    try:
        with context.local(log_level='info'):
            progress = log.progress("Fuzzing format strings...")

        for i in range(1, max):
            with context.local(log_level='info'):
                progress.status(f'{(i-1)/(max-1) * 100}%')
            p = process(stdin=PTY, stdout=PTY)
            index = -1
            for step in route:
                index += 1
                if b'ST%1$pEN' in step:
                    send_payload(i, step, p, progress)
                else:
                    p.sendline(step)
                if index == fmt_index:
                    scan(i, p, keyword, elf, libc, offset, libcs, pies, canaries)
            p.close()
    except KeyboardInterrupt:
        summary(progress, offset, canaries, pies, libcs)
    else:
        summary(progress, offset, canaries, pies, libcs)

# --- get route to format string ---
def get_route():
    route = []
    keyword = []
    fmt_index = -1
    p = process(stdin=PTY, stdout=PTY)
    click.secho('--- binary start ---', fg='cyan')
    ou = bytes.decode(p.clean(), 'utf-8')
    click.echo(ou, nl=False)
    while (match := regex.search("ST((?:0x[0-9a-f]+)|(?:\(nil\)))EN", ou)) == None:
        inp = bytes(input().strip(), 'utf-8')
        p.sendline(inp)
        route.append(inp)
        current = bytes.decode(p.clean(), 'utf-8')
        ou += current
        click.echo(current, nl=False)
        fmt_index += 1
    else:
        click.secho('\n--- binary end ---', fg='red')
        match = match.group(0)
        start = regex.search(f"([\w\W]*){match}", ou).group(1)
        end = regex.search(f"{match}([\w\W]*)", ou).group(1)
        keyword.append(bytes(start[-10:], 'utf-8'))
        keyword.append(bytes(end[:10], 'utf-8'))
        p.close()
        return route, fmt_index, keyword

# --- send payload ---
def send_payload(i, step, p, progress):
    with context.local(log_level='info'):
        progress.status(f'{(i-1)/200 * 100}%')
    payload = step.replace(b'ST%1$pEN', bytes(f'%{i}$p', 'utf-8'))
    p.sendline(payload)

# --- scan output for potential leaks ---
def scan(i, p, keyword, elf, libc, offset, libcs, pies, canaries):
    if libc != None:
        libc_base = p.libs()[libc.path]
    p.recvuntil(keyword[0])
    if keyword[1] != b'':
        leak = p.recvuntil(keyword[1], drop=True).strip()
    else:
        leak = p.clean().strip()
    if offset_check(leak, i):
        click.secho('Offset found', fg='blue')
        offset.append(i)
    elif len(libcs) < 5:
        if (libc_offset := libc_check(leak, elf, libc_base)) != False: 
            click.secho(f'Possible LIBC leak with offset {hex(libc_offset)} found', fg='green')
            libcs[i] = libc_offset
    elif elf.pie and (symbol := pie_check(leak, elf)) != False:
        click.secho(f'Possible PIE leak of {symbol} found', fg='cyan')
        if pies.get(symbol):
            pies[symbol].append(i)
        else:
            pies[symbol] = [i]
    elif elf.canary and canary_check(leak, elf):
        click.secho('Possible canary found', fg='yellow')
        canaries.append(i)

# --- summarize leaks ---
def summary(progress, offset, canaries, pies, libcs):
    with context.local(log_level='info'):
        progress.success('Done!')
    click.secho('\n--- Summary ---', fg='cyan')
    if offset != []:
        click.secho('Offset:', underline=True)
        click.secho(f'\t%{offset[0]}$p', fg='blue')
    if libcs != {}:
        click.secho('Possible LIBC leaks: (libc_base = fmtstr_leak - offset)', underline=True)
        for i in libcs:
            click.secho(f'\t%{i}$p (offset = {hex(libcs[i])})', fg='green')
    if pies != {}:
        click.secho('Possible PIE leaks:', underline=True)
        for i in pies:
            click.secho(f'\t{i}: ' + ', '.join([f'%{j}$p' for j in pies[i]]), fg='cyan')
    if canaries != []:
        click.secho('Possible canaries:', underline=True)
        for canary in canaries:
            click.secho(f'\t%{canary}$p', fg='yellow')

# --- check if leak is offset ---
def offset_check(leak, i):
    try:
        leak = pack(int(bytes.decode(leak, 'utf-8'), 16))
        assert b'%' in leak and b'$' in leak and bytes(str(i), 'utf-8') in leak
    except:
        return False
    else:
        return True

# --- check if leak is possible pie leak ---
def pie_check(leak, elf):
    try:
        leak = int(bytes.decode(leak, 'utf-8'), 16)
        for i in elf.sym:
            test = hex(leak - elf.sym[i])
            if (test[2:4] == '55' or test[2:4] == '56') and test[-2:] == '00':
                return i
        return False
    except:
        return False

# --- check if leak is possible libc leak ---
def libc_check(leak, elf, libc_base):
    if elf.bits == 32:
        start = 'f7'
    elif elf.bits == 64:
        start = '7f'
    try:
        leak = int(bytes.decode(leak, 'utf-8'), 16)
        libc_offset = leak - libc_base
        assert hex(leak)[2:4] == start and libc_offset >= 0
    except:
        return False
    else:
        return libc_offset

# --- check if leak is possible canary ---
def canary_check(leak, elf):
    leak = bytes.decode(leak, 'utf-8')
    if elf.bits == 64:
        if len(leak) == 18:
            if leak[16:] == '00':
                return True
    elif elf.bits == 32:
        if len(leak) == 10:
            if leak[8:] == '00':
                return True
    return False
