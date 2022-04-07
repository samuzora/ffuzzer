# ffuzzer

ffuzzer (inspired by f-string `f'fuzzer'`) is a fuzzer for format string vulnerabilities, commonly found in CTFs. When trying to exploit a format string leak, I usually waste time scripting a custom fuzzer for that specific challenge. With this fuzzer, I hope to eliminate the repetitive process of fuzzing format string read primitives.

## What can it do?
Currently, the fuzzer can fuzz:

1. Input offset
2. Canary leaks
3. PIE leaks
4. LIBC base (ASLR) leaks

## Installation
```
pip install ffuzzer
```

## Usage
```
ffuzzer --help
```

## Bugs?
If you find any bugs, it'd be greatly appreciated if you could open an issue. I'll try my best to resolve the issue.

Please also include the binary you're trying to exploit to speed up the debugging process.
