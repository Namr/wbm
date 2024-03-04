use clap::Parser;
use nix::{
    sys::{ptrace, stat, wait},
    unistd::Pid,
};
use num_traits::FromPrimitive;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::{read_dir, File};
use std::io::{prelude::*, BufReader};
use std::net::Ipv4Addr;
use std::path::Path;

mod unistd_64;

use unistd_64::*;

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

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct SocketAddress {
    addr: Ipv4Addr,
    port: u16,
}

#[derive(Debug, Copy, Clone)]
struct Socket {
    owning_pid: i32,
    inode: u64,
    s_type: SocketType,
    local_ip: SocketAddress,
    remote_ip: SocketAddress,
}

#[derive(Debug)]
struct SocketFdParseError;

#[derive(Debug)]
struct OsStringConvertError;

impl Error for SocketFdParseError {}
impl fmt::Display for SocketFdParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Could not parse process file system")
    }
}

impl Error for OsStringConvertError {}
impl fmt::Display for OsStringConvertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Could not convert OsString to String")
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
        }
        _ => panic!(
            "Process {} changed state but not to a stopped state!",
            pid.as_raw()
        ),
    }
}

fn describe_fd(pid: Pid, fd: u64) -> Option<FileDescriptor> {
    let path = format!("/proc/{}/fd/{}", pid.as_raw(), fd);
    match stat::stat(path.as_str()) {
        Ok(file_stats) => {
            // TODO: Add actual files to this as those are extremely common blocking ops
            let fd_type = if file_stats.st_mode & IF_SOCKET == IF_SOCKET {
                FdType::Socket
            } else {
                FdType::Unknown
            };
            let inode = file_stats.st_ino;
            Some(FileDescriptor { fd_type, inode })
        }
        Err(_) => None,
    }
}

fn find_all_pids_serving_address(address: SocketAddress) -> Result<Vec<i32>, Box<dyn Error>> {
    let mut pids = vec![];
    let process_dir_paths = read_dir("/proc")?;
    for maybe_path in process_dir_paths {
        let path = maybe_path?;
        if path.file_type()?.is_dir() {
            let path_str = match path.file_name().into_string() {
                Ok(str) => str,
                Err(_) => return Err(Box::new(OsStringConvertError {})),
            };
            match path_str.parse::<i32>() {
                Ok(pid) => {
                    // check all fds for this pid
                    let fd_paths = read_dir(format!("/proc/{}/fd", pid))?;
                    for maybe_fd_path in fd_paths {
                        let fd_path = maybe_fd_path?;
                        let fd_str = match fd_path.file_name().into_string() {
                            Ok(str) => str,
                            Err(_) => return Err(Box::new(OsStringConvertError {})),
                        };
                        match fd_str.parse::<u64>() {
                            Ok(fd) => {
                                let ppid = Pid::from_raw(pid);
                                let maybe_fd = describe_fd(ppid, fd);
                                if maybe_fd.is_some() && maybe_fd.unwrap().fd_type == FdType::Socket
                                {
                                    let sockets = describe_open_sockets(ppid);
                                    if sockets.is_ok() {
                                        let socket = sockets
                                            .unwrap()
                                            .into_iter()
                                            .find(|s| s.inode == maybe_fd.unwrap().inode)
                                            .ok_or(
                                                "error finding socket with corresponding fd inode",
                                            );
                                        if socket.is_ok() {
                                            if socket.unwrap().local_ip == address {
                                                pids.push(pid);
                                            }
                                        }
                                    }
                                }
                            }
                            _ => (),
                        }
                    }
                    // if fd matches inode add it to the list
                }
                _ => (),
            }
        }
    }
    Ok(pids)
}

fn describe_open_sockets(pid: Pid) -> Result<Vec<Socket>, Box<dyn Error>> {
    // open /proc/net/tcp and parse all entries into Sockets
    let s_path = format!("/proc/{}/net/tcp", pid.as_raw());
    let path = Path::new(s_path.as_str());
    let tcp_file = File::open(path)?;
    let tcp_reader = BufReader::new(tcp_file);
    let mut sockets: Vec<Socket> = vec![];

    for maybe_line in tcp_reader.lines() {
        let line = maybe_line?;
        let split_line: Vec<&str> = line.split_whitespace().collect();
        if split_line.len() != 17 {
            continue;
        }

        // local address is entry 1
        let local_addr_list: Vec<&str> = split_line[1].split_terminator(':').collect();
        let local_ip = SocketAddress {
            addr: Ipv4Addr::from(u32::from_str_radix(local_addr_list[0], 16)?.to_be()),
            port: u16::from_str_radix(local_addr_list[1], 16)?,
        };

        // remote address is entry 2
        let remote_addr_list: Vec<&str> = split_line[2].split_terminator(':').collect();
        let remote_ip = SocketAddress {
            addr: Ipv4Addr::from(u32::from_str_radix(remote_addr_list[0], 16)?.to_be()),
            port: u16::from_str_radix(remote_addr_list[1], 16)?,
        };

        // inode is entry 9
        let inode: u64 = split_line[9].parse()?;

        // insert into socket hashmap
        let socket = Socket {
            owning_pid: pid.as_raw(),
            inode,
            s_type: SocketType::TCP,
            local_ip,
            remote_ip,
        };
        sockets.push(socket);
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
        let local_ip = SocketAddress {
            addr: Ipv4Addr::from(u32::from_str_radix(local_addr_list[0], 16)?.to_be()),
            port: u16::from_str_radix(local_addr_list[1], 16)?,
        };

        // remote address is entry 2
        let remote_addr_list: Vec<&str> = split_line[2].split_terminator(':').collect();
        let remote_ip = SocketAddress {
            addr: Ipv4Addr::from(u32::from_str_radix(remote_addr_list[0], 16)?.to_be()),
            port: u16::from_str_radix(remote_addr_list[1], 16)?,
        };

        // inode is entry 9
        let inode: u64 = split_line[9].parse()?;

        // insert into socket hashmap
        let socket = Socket {
            owning_pid: pid.as_raw(),
            inode,
            s_type: SocketType::UDP,
            local_ip,
            remote_ip,
        };
        sockets.push(socket);
    }

    Ok(sockets)
}

fn interrogate_pid_for_block(pid: Pid) {
    ptrace::attach(pid).unwrap_or_else(|_| panic!("Could not attach to process {}", pid.as_raw()));
    execute_after_stopped(pid, || {
        ptrace::syscall(pid, None).unwrap_or_else(|_| {
            panic!(
                "Failed to wait for process {} to issue a syscall",
                pid.as_raw()
            )
        });
        execute_after_stopped(pid, || match ptrace::getregs(pid) {
            Ok(regs) => match FromPrimitive::from_u64(regs.orig_rax) {
                Some(SystemCall::Read) => {
                    let fd =
                        describe_fd(pid, regs.rdi).expect("Failed to get fd stats for process");
                    println!("process {} is waiting for a Read operation on file descriptor {} which is a {:?}", pid.as_raw(), regs.rdi, fd.fd_type);
                    if fd.fd_type == FdType::Socket {
                        let sockets = describe_open_sockets(pid)
                            .expect("failed to describe sockets for the blocked process");
                        let socket = sockets
                            .iter()
                            .find(|s| s.inode == fd.inode)
                            .expect("couldn't find a socket with the fd's inode");
                        println!(
                            "blocked socket is listening for a message from {}",
                            socket.remote_ip
                        );

                        match find_all_pids_serving_address(socket.remote_ip) {
                            Ok(pids) if pids.len() == 1 => {
                                println!("That IP is being served on this system by {:?}", pids[0]);
                                interrogate_pid_for_block(Pid::from_raw(pids[0]));
                            }
                            _ => (),
                        }
                        // if its a socket, lets find and print more information about it
                        // TODO
                    }
                }
                Some(other) => println!(
                    "process {} is waiting for syscall {:?}",
                    pid.as_raw(),
                    other
                ),
                None => println!(
                    "process is waiting for unrecognized syscall with id {}",
                    regs.orig_rax
                ),
            },
            Err(errno) => println!("Get registers from process failed with code {}", errno),
        });
    });
    ptrace::detach(pid, None)
        .unwrap_or_else(|_| panic!("Failed to detach from process {}", pid.as_raw()));
}

fn main() {
    let args = Args::parse();
    let pid = Pid::from_raw(args.pid);
    interrogate_pid_for_block(pid);
}
