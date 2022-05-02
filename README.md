# ffuzzer

ffuzzer (`f'fuzzer'`) is a fuzzer for format string vulnerabilities, commonly found in CTFs. 

When trying to exploit a format string leak, I usually waste time scripting a custom fuzzer for 
that specific challenge. With this fuzzer, I hope to eliminate the repetitive process of 
fuzzing format string read primitives.

ffuzzer features a 0-scripting required experience. Simply invoke ffuzzer on any binary, 
lead the program to the format string vuln, and copy-paste the provided payload. Once a leak is 
detected, the program will autmatically start fuzzing.

ffuzzer is currently targeted towards *full RELRO* format strings with *secondary buffer overflow*.
If you'd like to automate %n arbitrary writes, do check out pwntools's fmtstr_payload. 
Of course, ffuzzer also gives you your offset, so you can use it as well ;)

## What can it do?

Currently, the fuzzer can fuzz:

1. Input offset (100% accuracy)
2. PIE leaks (99% accuracy)
4. LIBC base (ASLR) leaks (50% accuracy)
4. Canary leaks (80% accuracy)

![ffuzzer in action!](./files/ffuzzer.svg)

> Percentages calculated based on intuition

### Features:

* No need to script route to format string vuln
* Automatic detection of leak type (input, PIE, LIBC or canary)
* Colour-coded output to look nice

## Installation

```
python3 -m pip install ffuzzer
```

## Usage

```
samuzora in ffuzzer on  main
at 16:49:06 ❯ ffuzzer --help
Usage: ffuzzer [OPTIONS] BINARY

  Automatic format string fuzzer by samuzora.

  Currently, this fuzzer can fuzz:

      1. Input offset

      2. Canary leaks

      3. PIE leaks

      4. LIBC base (ASLR) leaks

  On loading the binary, the fuzzer needs you to tell it how to get to the
  format string vuln.  Input ST%1$pEN where you'd expect the format string
  leak to be. When the program detects a leak, fuzzing will start
  automatically.

  You can CTRL+C anytime during the fuzzing, the fuzzer will output the
  summary of the leaks.

Options:
  -x, --max INTEGER  The maximum number of offsets to fuzz. Defaults to 200.
  --help             Show this message and exit.
```

```
ffuzzer ./binary
```

## Plans

The end goal of ffuzzer is to fully automate format-string exploitation, **including** arbitrary 
writes, even on remote. Ideally, this would be as simple as invoking ffuzzer with a flag specifying 
the desired function to jump to if possible, leading ffuzzer to the vuln, and letting ffuzzer take 
care of the rest, whether it's full RELRO format string buffer overflow, or partial RELRO format 
string writes. This tool will always remain fully open-source :)


## Bugs?

If you find any bugs, it'd be greatly appreciated if you could open an issue. I'll try my best to resolve the issue.

Please also include the binary you're trying to exploit to speed up the debugging process.
