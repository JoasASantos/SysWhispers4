"""
SysWhispers4 - Obfuscation Utilities
Provides name randomization, stub ordering, SSN encryption, string encryption,
and junk instruction injection helpers.
"""
from __future__ import annotations
import random
import string
from typing import List


class Obfuscator:
    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)

    # -----------------------------------------------------------------------
    # Random identifier generation
    # -----------------------------------------------------------------------

    def random_prefix(self, length: int = 4) -> str:
        """Return a random alphabetic prefix to replace the default 'SW4_'."""
        return "".join(self._rng.choices(string.ascii_uppercase, k=1) +
                       self._rng.choices(string.ascii_letters, k=length - 1)) + "_"

    def random_name(self, base: str) -> str:
        """Replace a known prefix in base with a random one (for stub symbols)."""
        suffix = "".join(self._rng.choices(string.ascii_letters + string.digits, k=6))
        return f"_SW4_{suffix}_{base}"

    def random_var_name(self, length: int = 8) -> str:
        """Generate a random variable name for obfuscation."""
        first = self._rng.choice(string.ascii_letters + "_")
        rest = "".join(self._rng.choices(string.ascii_letters + string.digits + "_", k=length - 1))
        return first + rest

    # -----------------------------------------------------------------------
    # Stub / function ordering randomization
    # -----------------------------------------------------------------------

    def shuffle_functions(self, functions: List[str]) -> List[str]:
        """Return a shuffled copy of the function list."""
        shuffled = list(functions)
        self._rng.shuffle(shuffled)
        return shuffled

    # -----------------------------------------------------------------------
    # SSN XOR encryption
    # -----------------------------------------------------------------------

    def generate_xor_key(self) -> int:
        """Generate a 32-bit XOR key for SSN encryption."""
        return self._rng.randint(0x01010101, 0xFEFEFEFE)

    @staticmethod
    def xor_ssn(ssn: int, key: int) -> int:
        """XOR-encrypt a single SSN with the given key."""
        return ssn ^ key

    @staticmethod
    def decrypt_c_macro(prefix: str, key: int) -> str:
        """Return a C preprocessor macro that decrypts an XOR'd SSN at runtime."""
        return (
            f"#define {prefix}DECRYPT_SSN(v) ((v) ^ 0x{key:08X}U)\n"
        )

    # -----------------------------------------------------------------------
    # Compile-time string encryption (RC4)
    # -----------------------------------------------------------------------

    def generate_rc4_key(self, length: int = 16) -> bytes:
        """Generate a random RC4 key for string encryption."""
        return bytes(self._rng.randint(0, 255) for _ in range(length))

    @staticmethod
    def rc4_encrypt(data: bytes, key: bytes) -> bytes:
        """RC4-encrypt raw bytes."""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xFF
            S[i], S[j] = S[j], S[i]
        i = j = 0
        out = []
        for byte in data:
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out.append(byte ^ S[(S[i] + S[j]) & 0xFF])
        return bytes(out)

    @staticmethod
    def encrypt_string_rc4_c(s: str, key_bytes: bytes, var_name: str) -> str:
        """Return C code for an RC4-encrypted string with per-string inline decryptor."""
        raw = s.encode("utf-8") + b"\x00"
        encrypted = Obfuscator.rc4_encrypt(raw, key_bytes)
        hex_arr = ", ".join(f"0x{b:02X}" for b in encrypted)
        key_hex = ", ".join(f"0x{b:02X}" for b in key_bytes)
        klen = len(key_bytes)
        slen = len(encrypted)
        return (
            f"static BYTE {var_name}_enc[{slen}] = {{ {hex_arr} }};\n"
            f"static const BYTE {var_name}_key[{klen}] = {{ {key_hex} }};\n"
            f"static __inline char* {var_name}_dec(void) {{\n"
            f"    BYTE S[256], tmp; int si, sj, n;\n"
            f"    for (n = 0; n < 256; n++) S[n] = (BYTE)n;\n"
            f"    for (n = 0, sj = 0; n < 256; n++) {{\n"
            f"        sj = (sj + S[n] + {var_name}_key[n % {klen}]) & 0xFF;\n"
            f"        tmp = S[n]; S[n] = S[sj]; S[sj] = tmp;\n"
            f"    }}\n"
            f"    si = 0; sj = 0;\n"
            f"    for (n = 0; n < {slen}; n++) {{\n"
            f"        si = (si + 1) & 0xFF;\n"
            f"        sj = (sj + S[si]) & 0xFF;\n"
            f"        tmp = S[si]; S[si] = S[sj]; S[sj] = tmp;\n"
            f"        {var_name}_enc[n] ^= S[(S[si] + S[sj]) & 0xFF];\n"
            f"    }}\n"
            f"    return (char*){var_name}_enc;\n"
            f"}}\n"
        )

    # Legacy XOR string encryption (kept for backwards compatibility)
    def generate_string_key(self) -> int:
        """Generate an 8-bit key for compile-time string XOR (legacy)."""
        return self._rng.randint(0x01, 0xFE)

    @staticmethod
    def encrypt_string_c(s: str, key: int, var_name: str) -> str:
        """Return C code for an XOR-encrypted string (legacy, prefer RC4)."""
        raw = s.encode("utf-8")
        encoded = [((b ^ key) & 0xFF) for b in raw]
        encoded.append(key)
        hex_arr = ", ".join(f"0x{b:02X}" for b in encoded)
        return (
            f"static BYTE {var_name}_enc[] = {{ {hex_arr} }};\n"
            f"static __inline char* {var_name}_dec(void) {{\n"
            f"    for (int i = 0; i < sizeof({var_name}_enc); i++)\n"
            f"        {var_name}_enc[i] ^= 0x{key:02X};\n"
            f"    return (char*){var_name}_enc;\n"
            f"}}\n"
        )

    # -----------------------------------------------------------------------
    # Junk instruction insertion (for ASM stubs)
    # -----------------------------------------------------------------------

    def junk_instructions(self, count: int | None = None) -> str:
        """Generate junk instructions that resemble real code (MASM syntax).

        Uses r11 as scratch register (caller-saved/volatile in x64 ABI,
        not part of syscall parameter passing). Every pattern is net-neutral
        on all registers that matter for the syscall stub.
        """
        n = count if count is not None else self._rng.randint(2, 5)

        imm8 = lambda: self._rng.randint(1, 0xFF)
        imm32 = lambda: self._rng.randint(0x10000, 0x7FFFFFFF)

        patterns = [
            # Arithmetic that cancels (different random values each time)
            lambda: f"add r11d, 0{imm8():02X}h\n    sub r11d, 0{imm8():02X}h",
            lambda: f"sub r11d, 0{imm8():02X}h\n    add r11d, 0{imm8():02X}h",
            # Rotate cancellation
            lambda: (lambda s=self._rng.randint(1, 15):
                     f"rol r11d, {s}\n    ror r11d, {s}")(),
            lambda: (lambda s=self._rng.randint(1, 15):
                     f"ror r11d, {s}\n    rol r11d, {s}")(),
            # Double XOR with different immediates (looks like real crypto)
            lambda: (lambda v=imm32():
                     f"xor r11d, 0{v:08X}h\n    xor r11d, 0{v:08X}h")(),
            # Fake conditional that never branches
            lambda: f"xor r11d, r11d\n    jnz $+2",
            lambda: f"or r11d, 0FFFFFFFFh\n    jz $+2",
            # Stack push/pop — looks like real prologue
            lambda: "push r11\n    pop r11",
            # Bit manipulation pairs
            lambda: "bswap r11d\n    bswap r11d",
            lambda: "not r11d\n    not r11d",
            lambda: "neg r11d\n    neg r11d",
            # Fake comparison with random immediates (looks like bounds check)
            lambda: f"mov r11d, 0{imm32():08X}h\n    cmp r11d, 0{imm32():08X}h",
            # LEA with random displacement (looks like address calc)
            lambda: (lambda d=self._rng.randint(0x10, 0x7F):
                     f"lea r11, [r11 + {d}]\n    lea r11, [r11 - {d}]")(),
            # Shift cancellation
            lambda: (lambda s=self._rng.randint(1, 7):
                     f"shl r11d, {s}\n    shr r11d, {s}")(),
            # Test with random immediate (no side effects on r11)
            lambda: f"test r11d, 0{imm32():08X}h",
        ]

        selected = self._rng.choices(patterns, k=n)
        return "\n    ".join(p() for p in selected)

    def junk_nops(self, count: int | None = None) -> str:
        """Deprecated alias for junk_instructions."""
        return self.junk_instructions(count)

    def junk_instructions_gas(self, count: int | None = None) -> str:
        """Generate junk instructions for GAS inline assembly (AT&T/Intel hybrid).

        Same philosophy as MASM variant: real-looking operations on r11.
        Returns lines joined for embedding in GAS __asm__ quoted strings.
        """
        n = count if count is not None else self._rng.randint(2, 4)

        imm8 = lambda: self._rng.randint(1, 0xFF)
        imm32 = lambda: self._rng.randint(0x10000, 0x7FFFFFFF)

        patterns = [
            lambda: f"add r11d, {imm8()}\\n\\t\"\n        \"    sub r11d, {imm8()}",
            lambda: f"sub r11d, {imm8()}\\n\\t\"\n        \"    add r11d, {imm8()}",
            lambda: (lambda s=self._rng.randint(1, 15):
                     f"rol r11d, {s}\\n\\t\"\n        \"    ror r11d, {s}")(),
            lambda: (lambda v=imm32():
                     f"xor r11d, 0x{v:08X}\\n\\t\"\n        \"    xor r11d, 0x{v:08X}")(),
            lambda: "push r11\\n\\t\"\n        \"    pop r11",
            lambda: "bswap r11d\\n\\t\"\n        \"    bswap r11d",
            lambda: "not r11d\\n\\t\"\n        \"    not r11d",
            lambda: f"mov r11d, 0x{imm32():08X}\\n\\t\"\n        \"    cmp r11d, 0x{imm32():08X}",
            lambda: f"test r11d, 0x{imm32():08X}",
        ]

        selected = self._rng.choices(patterns, k=n)
        return "\\n\\t\"\n        \"    ".join(p() for p in selected)

    def junk_nops_gas(self, count: int | None = None) -> str:
        """Deprecated alias for junk_instructions_gas."""
        return self.junk_instructions_gas(count)

    # -----------------------------------------------------------------------
    # Egg value generation
    # -----------------------------------------------------------------------

    def generate_egg(self) -> int:
        """Return a random 64-bit egg value (used as placeholder for syscall)."""
        # Avoid 0x0F05 (syscall) sequences anywhere in the 8 bytes
        while True:
            v = self._rng.randint(0x0101010101010101, 0xFEFEFEFEFEFEFEFE)
            # Ensure the byte sequence doesn't accidentally contain 0F 05
            raw = v.to_bytes(8, "little")
            if b"\x0f\x05" not in raw:
                return v

    @staticmethod
    def egg_asm_bytes(egg: int) -> str:
        """Return MASM DB directive for the 8-byte egg."""
        b = list(egg.to_bytes(8, "little"))
        return "DB " + ", ".join(f"{x:02X}h" for x in b)

    # -----------------------------------------------------------------------
    # Guard page token generation (for anti-debug)
    # -----------------------------------------------------------------------

    def generate_canary(self) -> int:
        """Generate a 32-bit canary value for integrity checks."""
        return self._rng.randint(0x10000000, 0xEFFFFFFF)
