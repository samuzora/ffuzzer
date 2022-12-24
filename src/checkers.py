from pwn import *

# --- check if leak is offset ---
def offset_check(leak, i):
    try:
        decoded_leak = pack(int(leak.decode(), 16))
        assert f"%{i}$p".encode() in decoded_leak
    except:
        return False
    else:
        return True


# --- check if leak is possible pie leak ---
def pie_check(leak, elf):
    try:
        decoded_leak = int(leak.decode(), 16)
        for symbol in elf.sym:
            pie_base = hex(decoded_leak - elf.sym[symbol])
            if (pie_base[2:4] == "55" or pie_base[2:4] == "56") and pie_base[-2:] == "00":
                return symbol
        return False
    except:
        return False


# --- check if leak is possible libc leak ---
def libc_check(leak, elf, libc_base):
    if elf.bits == 32:
        start = "f7"
    elif elf.bits == 64:
        start = "7f"
    try:
        leak = int(leak.decode(), 16)
        libc_offset = leak - libc_base
        assert hex(leak)[2:4] == start and libc_offset >= 0
    except:
        return False
    else:
        return libc_offset


# --- check if leak is possible canary ---
def canary_check(leak, elf):
    leak = leak.decode()
    if elf.bits == 64:
        if len(leak) == 18:
            if leak[16:] == "00":
                return True
    elif elf.bits == 32:
        if len(leak) == 10:
            if leak[8:] == "00":
                return True
    return False


# --- check for custom value ---
def custom_check(leak, custom):
    try:
        leak = leak.decode()
        if custom in leak:
            return True
    except:
        return False
