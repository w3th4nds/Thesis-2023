<p align="center">
<img src="assets/logo.png" alt="drawing" width="300px" />
<h2 align="center"> Nikolaos-Athanasios Sarridis </h2>   
<h2 align="center"> 711151026</h2>
</p>

  My thesis focuses on finding, triggering, abusing, explaining, and exploiting common vulnerabilities when writing a C/C++ program and are related to program security. Someone can take advantage of these vulnerabilities and gain access to the system or read confidential files that he/she is not allowed to. Our goal is to eliminate these programming "errors" that trigger a bug (from the defensive side) and learn how to find such flaws to patch them and write more secure code.
Some of the bugs we will see are

* `Buffer Overflows`,
* `Format Strings`,
* `Integer Overflows`,
* and `Off-by-one`.

We will exploit these bugs by using these techniques:

`ret2libc`,
`ret2csu`,
`ret2shellcode`,
`one gadget`.

All the bugs above will be implemented in Linux binary files (ELF) and will run in virtual environments (Docker). There will be step-by-step guidance on how to:

* approach these challenges,
* find and trigger the bugs,   
* and exploit them.

In the end, there will be a python script that will give us access to the system and an explanation of how to patch the program to prevent each error.


This repo contains all the files needed to:
* build
* play
* solve

The challanges demonstrated in my Thesis.
<center>
| Challenge                  | Objective               | zip                                                   | 
| :---:                      | :---:                   | :---:                                                 |
| [challenge0](./challenge0) | Overwrite a var's value | [challenge0.zip](./challenge0/release/challenge0.zip) |
| [challenge1](./challenge1) | **ret2win**             | [challenge1.zip](./challenge1/release/challenge1.zip) |
| [challenge2](./challenge2) | **ret2win** with args   | [challenge2.zip](./challenge2/release/challenge2.zip) |
| [challenge3](./challenge3) | **ret2shellcode**       | [challenge3.zip](./challenge3/release/challenge3.zip) |
| [challenge4](./challenge4) | **integer overflow**    | [challenge4.zip](./challenge4/release/challenge4.zip) |
| [challenge5](./challenge5) | **off by one**          | [challenge5.zip](./challenge5/release/challenge5.zip) |
| [challenge6](./challenge6) | **ret2libc**            | [challenge6.zip](./challenge6/release/challenge6.zip) |
| [challenge7](./challenge7) | **ret2csu**             | [challenge7.zip](./challenge8/release/challenge7.zip) |
| [challenge8](./challenge8) | **fmtstr-canary-PIE**   | [challenge8.zip](./challenge9/release/challenge8.zip) |
| [challenge9](./challenge9) | **one gadget**          | [challenge9.zip](./challenge9/release/challenge9.zip) |
</center>
