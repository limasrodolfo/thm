#!/usr/bin/env python3

"""
XOR Repeating Key Decryptor
Author: Rodolfo Lima
Description: Recover XOR key using known-plaintext attack and decrypt message
THM: https://tryhackme.com/room/w1seguy
"""

DEBUG = False  # Change to True to get the full output.

HEX_CIPHER = "0e1c1c31446b353d24401f2c250b402e603221571b3a23795536182822612820287a41282c1e3849"
KNOWN_PLAINTEXT = b"THM{}"


def debug(msg):
    if DEBUG:
        print(msg)


def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)


def show_cipher_bytes(cipher):
    debug("[DEBUG-01] Cipher bytes:")
    for i, b in enumerate(cipher):
        debug(f"  [{i:02}] 0x{b:02x}")


def recover_xor_key(cipher, known):
    key = bytearray()

    debug("\n[DEBUG-02] Recovering XOR key:")

    for i in range(len(known) - 1):
        k = cipher[i] ^ known[i]
        debug(
            f"[DEBUG-03] 0x{cipher[i]:02x} XOR 0x{known[i]:02x} "
            f"('{chr(known[i])}') = 0x{k:02x}"
        )
        key.append(k)

    k = cipher[-1] ^ known[-1]
    debug(
        f"[DEBUG-04] last_byte 0x{cipher[-1]:02x} XOR "
        f"0x{known[-1]:02x} ('}}') = 0x{k:02x}"
    )
    key.append(k)

    return bytes(key)


def xor_decrypt(cipher, key):
    plaintext = bytearray()

    debug("\n[DEBUG-05] Decrypting with repeating XOR key:")

    for i, b in enumerate(cipher):
        p = b ^ key[i % len(key)]
        debug(
            f"[DEBUG-06] 0x{b:02x} XOR 0x{key[i % len(key)]:02x} "
            f"-> 0x{p:02x} ('{chr(p)}')"
        )
        plaintext.append(p)

    return plaintext


def main():
    cipher = hex_to_bytes(HEX_CIPHER)

    show_cipher_bytes(cipher)

    key = recover_xor_key(cipher, KNOWN_PLAINTEXT)
    debug(f"\n[DEBUG-07] Recovered key: {key}")

    plaintext = xor_decrypt(cipher, key)

    print("\n[+] Final plaintext:")
    print(plaintext.decode(errors="ignore"))


if __name__ == "__main__":
    main()
