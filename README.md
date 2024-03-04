# wbm: Who's Blocking Me?
[![GPL](https://img.shields.io/github/license/Namr/wbm)](https://github.com/namr/wbm/blob/main/LICENSE-GPL)

wbm is a small command line utility that tries to help understand why a process may be deadlocked. It checks to see if a process is blocking on a system call. It's main usecase is for systems with many locally served TCP connections. In scenarios where a process is blocked on a TCP read, wbm can find which process is responsible for serving the read, and recursively find why that other process may be blocked.


## Limitations
* Currently only runs on 64bit Linux Machines
* Currently untested for multithreaded programs
