use num_derive::FromPrimitive;

// (note: amoussa) autogenerated with vim macros
#[derive(Debug, FromPrimitive, Copy, Clone)]
pub enum SystemCall {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Stat = 4,
    Fstat = 5,
    Lstat = 6,
    Poll = 7,
    Lseek = 8,
    Mmap = 9,
    Mprotect = 10,
    Munmap = 11,
    Brk = 12,
    RtSigaction = 13,
    RtSigprocmask = 14,
    RtSigreturn = 15,
    Ioctl = 16,
    Pread64 = 17,
    Pwrite64 = 18,
    Readv = 19,
    Writev = 20,
    Access = 21,
    Pipe = 22,
    Select = 23,
    SchedYield = 24,
    Mremap = 25,
    Msync = 26,
    Mincore = 27,
    Madvise = 28,
    Shmget = 29,
    Shmat = 30,
    Shmctl = 31,
    Dup = 32,
    Dup2 = 33,
    Pause = 34,
    Nanosleep = 35,
    Getitimer = 36,
    Alarm = 37,
    Setitimer = 38,
    Getpid = 39,
    Sendfile = 40,
    Socket = 41,
    Connect = 42,
    Accept = 43,
    Sendto = 44,
    Recvfrom = 45,
    Sendmsg = 46,
    Recvmsg = 47,
    Shutdown = 48,
    Bind = 49,
    Listen = 50,
    Getsockname = 51,
    Getpeername = 52,
    Socketpair = 53,
    Setsockopt = 54,
    Getsockopt = 55,
    Clone = 56,
    Fork = 57,
    Vfork = 58,
    Execve = 59,
    Exit = 60,
    Wait4 = 61,
    Kill = 62,
    Uname = 63,
    Semget = 64,
    Semop = 65,
    Semctl = 66,
    Shmdt = 67,
    Msgget = 68,
    Msgsnd = 69,
    Msgrcv = 70,
    Msgctl = 71,
    Fcntl = 72,
    Flock = 73,
    Fsync = 74,
    Fdatasync = 75,
    Truncate = 76,
    Ftruncate = 77,
    Getdents = 78,
    Getcwd = 79,
    Chdir = 80,
    Fchdir = 81,
    Rename = 82,
    Mkdir = 83,
    Rmdir = 84,
    Creat = 85,
    Link = 86,
    Unlink = 87,
    Symlink = 88,
    Readlink = 89,
    Chmod = 90,
    Fchmod = 91,
    Chown = 92,
    Fchown = 93,
    Lchown = 94,
    Umask = 95,
    Gettimeofday = 96,
    Getrlimit = 97,
    Getrusage = 98,
    Sysinfo = 99,
    Times = 100,
    Ptrace = 101,
    Getuid = 102,
    Syslog = 103,
    Getgid = 104,
    Setuid = 105,
    Setgid = 106,
    Geteuid = 107,
    Getegid = 108,
    Setpgid = 109,
    Getppid = 110,
    Getpgrp = 111,
    Setsid = 112,
    Setreuid = 113,
    Setregid = 114,
    Getgroups = 115,
    Setgroups = 116,
    Setresuid = 117,
    Getresuid = 118,
    Setresgid = 119,
    Getresgid = 120,
    Getpgid = 121,
    Setfsuid = 122,
    Setfsgid = 123,
    Getsid = 124,
    Capget = 125,
    Capset = 126,
    RtSigpending = 127,
    RtSigtimedwait = 128,
    RtSigqueueinfo = 129,
    RtSigsuspend = 130,
    Sigaltstack = 131,
    Utime = 132,
    Mknod = 133,
    Uselib = 134,
    Personality = 135,
    Ustat = 136,
    Statfs = 137,
    Fstatfs = 138,
    Sysfs = 139,
    Getpriority = 140,
    Setpriority = 141,
    SchedSetparam = 142,
    SchedGetparam = 143,
    SchedSetscheduler = 144,
    SchedGetscheduler = 145,
    SchedGetPriorityMax = 146,
    SchedGetPriorityMin = 147,
    SchedRRGetInterval = 148,
    Mlock = 149,
    Munlock = 150,
    Mlockall = 151,
    Munlockall = 152,
    Vhangup = 153,
    ModifyLdt = 154,
    PivotRoot = 155,
    Sysctl = 156,
    Prctl = 157,
    ArchPrctl = 158,
    Adjtimex = 159,
    Setrlimit = 160,
    Chroot = 161,
    Sync = 162,
    Acct = 163,
    Settimeofday = 164,
    Mount = 165,
    Umount2 = 166,
    Swapon = 167,
    Swapoff = 168,
    Reboot = 169,
    Sethostname = 170,
    Setdomainname = 171,
    Iopl = 172,
    Ioperm = 173,
    CreateModule = 174,
    InitModule = 175,
    DeleteModule = 176,
    GetKernelSyms = 177,
    QueryModule = 178,
    Quotactl = 179,
    Nfsservctl = 180,
    Getpmsg = 181,
    Putpmsg = 182,
    AfsSyscall = 183,
    Tuxcall = 184,
    Security = 185,
    Gettid = 186,
    Readahead = 187,
    Setxattr = 188,
    Lsetxattr = 189,
    Fsetxattr = 190,
    Getxattr = 191,
    Lgetxattr = 192,
    Fgetxattr = 193,
    Listxattr = 194,
    Llistxattr = 195,
    Flistxattr = 196,
    Removexattr = 197,
    Lremovexattr = 198,
    Fremovexattr = 199,
    Tkill = 200,
    Time = 201,
    Futex = 202,
    SchedSetaffinity = 203,
    SchedGetaffinity = 204,
    SetThreadArea = 205,
    IOSetup = 206,
    IODestroy = 207,
    IOGetevents = 208,
    IOSubmit = 209,
    IOCancel = 210,
    GetThreadArea = 211,
    LookupDcookie = 212,
    EpollCreate = 213,
    EpollCtlOld = 214,
    EpollWaitOld = 215,
    RemapFilePages = 216,
    Getdents64 = 217,
    SetTIDAddress = 218,
    RestartSyscall = 219,
    Semtimedop = 220,
    Fadvise64 = 221,
    TimerCreate = 222,
    TimerSettime = 223,
    TimerGettime = 224,
    TimerGetoverrun = 225,
    TimerDelete = 226,
    ClockSettime = 227,
    ClockGettime = 228,
    ClockGetres = 229,
    ClockNanosleep = 230,
    ExitGroup = 231,
    EpollWait = 232,
    EpollCtl = 233,
    Tgkill = 234,
    Utimes = 235,
    Vserver = 236,
    Mbind = 237,
    SetMempolicy = 238,
    GetMempolicy = 239,
    MqOpen = 240,
    MqUnlink = 241,
    MqTimedsend = 242,
    MqTimedreceive = 243,
    MqNotify = 244,
    MqGetsetattr = 245,
    KexecLoad = 246,
    Waitid = 247,
    AddKey = 248,
    RequestKey = 249,
    Keyctl = 250,
    IoprioSet = 251,
    IoprioGet = 252,
    InotifyInit = 253,
    InotifyAddWatch = 254,
    InotifyRmWatch = 255,
    MigratePages = 256,
    Openat = 257,
    Mkdirat = 258,
    Mknodat = 259,
    Fchownat = 260,
    Futimesat = 261,
    Newfstatat = 262,
    Unlinkat = 263,
    Renameat = 264,
    Linkat = 265,
    Symlinkat = 266,
    Readlinkat = 267,
    Fchmodat = 268,
    Faccessat = 269,
    Pselect6 = 270,
    Ppoll = 271,
    Unshare = 272,
    SetRobustList = 273,
    GetRobustList = 274,
    Splice = 275,
    Tee = 276,
    SyncFileRange = 277,
    Vmsplice = 278,
    MovePages = 279,
    Utimensat = 280,
    EpollPwait = 281,
    Signalfd = 282,
    TimerfdCreate = 283,
    Eventfd = 284,
    Fallocate = 285,
    TimerfdSettime = 286,
    TimerfdGettime = 287,
    Accept4 = 288,
    Signalfd4 = 289,
    Eventfd2 = 290,
    EpollCreate1 = 291,
    Dup3 = 292,
    Pipe2 = 293,
    InotifyInit1 = 294,
    Preadv = 295,
    Pwritev = 296,
    RtTgsigqueueInfo = 297,
    PerfEventOpen = 298,
    Recvmmsg = 299,
    FanotifyInit = 300,
    FanotifyMark = 301,
    Prlimit64 = 302,
    NameToHandleAt = 303,
    OpenByHandleAt = 304,
    ClockAdjTime = 305,
    Syncfs = 306,
    Sendmmsg = 307,
    Setns = 308,
    Getcpu = 309,
    ProcessVmReadv = 310,
    ProcessVmWritev = 311,
    Kcmp = 312,
    FinitModule = 313,
    SchedSetattr = 314,
    SchedGetattr = 315,
    Renameat2 = 316,
    Seccomp = 317,
    Getrandom = 318,
    MemfdCreate = 319,
    KexecFileLoad = 320,
    Bpf = 321,
    Execveat = 322,
    Userfaultfd = 323,
    Membarrier = 324,
    Mlock2 = 325,
    CopyFileRange = 326,
    Preadv2 = 327,
    Pwritev2 = 328,
    PkeyMprotect = 329,
    PkeyAlloc = 330,
    PkeyFree = 331,
    Statx = 332,
    IOPgetevents = 333,
    Rseq = 334,
    PidfdSendSignal = 424,
    IOUringSetup = 425,
    IOUringEnter = 426,
    IOUringRegister = 427,
    OpenTree = 428,
    MoveMount = 429,
    Fsopen = 430,
    Fsconfig = 431,
    Fsmount = 432,
    Fspick = 433,
    PidfdOpen = 434,
    Clone3 = 435,
    CloseRange = 436,
    Openat2 = 437,
    PidfdGetfd = 438,
    Faccessat2 = 439,
    ProcessMadvise = 440,
    EpollPwait2 = 441,
    MountSetattr = 442,
    QuotactlFd = 443,
    LandlockCreateRuleset = 444,
    LandlockAddRule = 445,
    LandlockRestrictSelf = 446,
    MemfdSecret = 447,
    ProcessMrelease = 448,
}
