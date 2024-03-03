use clap::Parser;
use std::error::Error;
use nix::{sys::{ptrace, wait, stat}, unistd::Pid};
use std::fs::File;
use std::fmt;
use std::net::Ipv4Addr;
use std::io::{prelude::*, BufReader};
use std::path::Path;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // PID of the process to investigate
    #[arg(short)]
    pid: i32,
}

const IF_SOCKET: u32 = 0o140000;

#[derive(Debug, Copy, Clone, PartialEq)]
enum FdType {
    Unknown,
    Socket,
}

#[derive(Debug, Copy, Clone)]
struct FileDescriptor {
    fd_type: FdType,
    inode: u64,
}

#[derive(Debug, Copy, Clone)]
enum SocketType {
    TCP,
    UDP,
}

#[derive(Debug, Copy, Clone)]
struct SocketAddress {
    addr: Ipv4Addr,
    port: u16, 
}

#[derive(Debug, Copy, Clone)]
struct Socket {
    inode: u64,
    s_type: SocketType,
    local_ip: SocketAddress,
    remote_ip: SocketAddress,
}

#[derive(Debug)]
struct SocketFdParseError;

impl Error for SocketFdParseError {}
impl fmt::Display for SocketFdParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Could not parse process file system")
    }
}


impl fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

fn execute_after_stopped(pid: Pid, f: impl Fn() -> ()) {
    match wait::waitpid(pid, None) {
        Ok(wait::WaitStatus::Stopped(_, _)) => {
            f();
        },
        _ => panic!("Process {} changed state but not to a stopped state!", pid.as_raw())
    }
}

fn describe_fd(pid: Pid, fd: u64) ->  Option<FileDescriptor> {
    let path = format!("/proc/{}/fd/{}", pid.as_raw(), fd);
    match stat::stat(path.as_str()) {
        Ok(file_stats) =>  {
            // TODO: Add actual files to this as those are extremely common blocking ops
            let fd_type = if file_stats.st_mode & IF_SOCKET == IF_SOCKET { FdType::Socket } else { FdType::Unknown };
            let inode = file_stats.st_ino;
            Some(FileDescriptor{fd_type, inode})
        },
        Err(_) => None
    }
}

fn describe_open_sockets(pid: Pid) -> Result<Vec<Socket>, Box<dyn Error>> {
    let mut sockets: Vec<Socket> = vec![];

    // open /proc/net/tcp and parse all entries into Sockets
    let s_path = format!("/proc/{}/net/tcp", pid.as_raw());
    let path = Path::new(s_path.as_str());
    let tcp_file = File::open(path)?;
    let tcp_reader = BufReader::new(tcp_file);

    for maybe_line in tcp_reader.lines() {
        let line = maybe_line?;
        let split_line: Vec<&str> = line.split_whitespace().collect();
        if split_line.len() != 17 {
            continue;
        }
        
        // local address is entry 1
        let local_addr_list: Vec<&str> = split_line[1].split_terminator(':').collect();
        let local_ip = SocketAddress{addr: Ipv4Addr::from(u32::from_str_radix(local_addr_list[0], 16)?.to_be()), port: u16::from_str_radix(local_addr_list[1], 16)?};
        
        // remote address is entry 2
        let remote_addr_list: Vec<&str> = split_line[2].split_terminator(':').collect();
        let remote_ip = SocketAddress{addr: Ipv4Addr::from(u32::from_str_radix(remote_addr_list[0], 16)?.to_be()), port: u16::from_str_radix(remote_addr_list[1], 16)?};
        
        // inode is entry 9
        let inode: u64 = split_line[9].parse()?;
        
        sockets.push(Socket{inode, s_type: SocketType::TCP, local_ip, remote_ip});
    }

    // open /proc/net/udp and parse all entries into Sockets
    let s_path = format!("/proc/{}/net/udp", pid.as_raw());
    let path = Path::new(s_path.as_str());
    let udp_file = File::open(path)?;
    let udp_reader = BufReader::new(udp_file);

    for maybe_line in udp_reader.lines() {
        let line = maybe_line?;
        let split_line: Vec<&str> = line.split_whitespace().collect();
        if split_line.len() != 13 {
            continue;
        }
        
        // local address is entry 1
        let local_addr_list: Vec<&str> = split_line[1].split_terminator(':').collect();
        let local_ip = SocketAddress{addr: Ipv4Addr::from(u32::from_str_radix(local_addr_list[0], 16)?.to_be()), port: u16::from_str_radix(local_addr_list[1], 16)?};
        
        // remote address is entry 2
        let remote_addr_list: Vec<&str> = split_line[2].split_terminator(':').collect();
        let remote_ip = SocketAddress{addr: Ipv4Addr::from(u32::from_str_radix(remote_addr_list[0], 16)?.to_be()), port: u16::from_str_radix(remote_addr_list[1], 16)?};
        
        // inode is entry 9
        let inode: u64 = split_line[9].parse()?;
        
        sockets.push(Socket{inode, s_type: SocketType::UDP, local_ip, remote_ip});
    }

    return Ok(sockets);
}

fn main() {
    let args =  Args::parse();
    let pid = Pid::from_raw(args.pid);
    let sockets = describe_open_sockets(pid).expect("Failed to parse the open sockets on this process");
    ptrace::attach(pid).unwrap_or_else(|_| panic!("Could not attach to process {}", args.pid));
     
    execute_after_stopped(pid, || {
        ptrace::syscall(pid, None).unwrap_or_else(|_| panic!("Failed to wait for process {} to issue a syscall", args.pid));
        execute_after_stopped(pid, || {
            match ptrace::getregs(pid) {
                Ok(regs) => match regs.orig_rax {
                    0 => {
                        let fd = describe_fd(pid, regs.rdi).expect("Failed to get fd stats for process");
                        println!("process is waiting for a READ operation on file descriptor {} which is a {:?}", regs.rdi, fd.fd_type);
                        if fd.fd_type == FdType::Socket {
                            match sockets.iter().find(|s| s.inode == fd.inode) {
                                Some(socket) => println!("socket is trying to read from ip: {} using {:?}", socket.remote_ip, socket.s_type),
                                _ => println!("Socket is reading from something we didn't find in the process filesystem..."),
                            }
                        }
                    },
                    n => println!("process is waiting for syscall #{}", n),
                },
                Err(errno) => println!("Get registers from process failed with code {}", errno),
            }
        });
    });
    ptrace::detach(pid, None).unwrap_or_else(|_| panic!("Failed to detach from process {}", args.pid));
}
