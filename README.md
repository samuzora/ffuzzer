# ffuzzer

ffuzzer (`f'fuzzer'`) is a fuzzer for format string vulnerabilities, commonly found in CTFs. 

When trying to exploit a format string leak, some time is usually spent scripting a custom fuzzer for that specific
challenge. With this fuzzer, I hope to eliminate the repetitive process of fuzzing format string read primitives.

ffuzzer features a 0-scripting required experience. Simply invoke ffuzzer on any binary, lead the program to the format
string vuln, and copy-paste the provided payload. Once a leak is detected, the program will autmatically start fuzzing.

ffuzzer is currently targeted towards *full RELRO* format strings with *secondary buffer overflow*. If you'd like to
automate %n arbitrary writes, do check out pwntools's fmtstr_payload. Of course, ffuzzer also gives you your offset, so
you can use it as well ;)

## What can it do?

Currently, the fuzzer can fuzz:

1. Input offset (100% accuracy)
2. PIE leaks (99% accuracy)
4. LIBC base (ASLR) leaks (50% accuracy)
4. Canary leaks (80% accuracy)

![ffuzzer in action!](./files/ffuzzer.svg)

> Percentages calculated based on intuition

### Features:

* By default, fuzzes extremely quickly (~2 seconds on average)
* Automatic detection of leak type (input offset, PIE, LIBC or canary)

## Installation

``` python3 -m pip install ffuzzer ```

## Usage

``` ffuzzer ./vuln```

You'll need to tell the program how to get to the format string bug and leak. At the input where you expect to have a
format string bug, input `ST%1$pEN`. You can append anything to the start or end, the program will handle it
accordingly.

Once a leak is detected, the program will trace back your steps to the payload input and begin fuzzing. That's all you
need to do :)

## Roadmap

The end goal of ffuzzer is to fully automate format-string exploitation, **including** arbitrary writes, even on remote.
This would be as simple as invoking ffuzzer with a flag specifying the desired function to jump to if possible,
leading ffuzzer to the vuln, and letting ffuzzer take care of the rest, whether it's full RELRO format string buffer
overflow, or partial RELRO format string writes. This tool will always remain fully open-source :)

## Bugs

If you find any bugs, it'd be greatly appreciated if you could open an issue. I'll try my best to resolve the issue.

Please also include the binary you're trying to exploit to speed up the debugging process.

ps. There's a common bug where the fuzzer freezes on certain binaries. Strangely, when printing anything (even an empty
string with no newline) the fuzzer unfreezes and the bug is resolved. If you happen to know what's going on backend, I'd
love it if you could let me know. Thanks!
