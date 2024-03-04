use nix::{sys::stat, unistd::Pid};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::{read_dir, File};
use std::io::{prelude::*, BufReader};
use std::net::Ipv4Addr;
use std::path::Path;

const IF_SOCKET: u32 = 0o140000;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FdType {
    Unknown,
    Socket,
}

#[derive(Debug, Copy, Clone)]
pub struct FileDescriptor {
    pub fd_type: FdType,
    pub inode: u64,
}

#[derive(Debug, Copy, Clone)]
pub enum SocketType {
    TCP,
    UDP,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct SocketAddress {
    pub addr: Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Copy, Clone)]
pub struct Socket {
    pub owning_pid: i32,
    pub inode: u64,
    pub s_type: SocketType,
    pub local_ip: SocketAddress,
    pub remote_ip: SocketAddress,
}

#[derive(Debug)]
pub struct SocketFdParseError;

#[derive(Debug)]
pub struct OsStringConvertError;

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

pub fn describe_fd(pid: Pid, fd: u64) -> Option<FileDescriptor> {
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

pub fn describe_all_open_sockets() -> Result<HashMap<SocketAddress, Socket>, Box<dyn Error>> {
    let mut open_sockets: HashMap<SocketAddress, Socket> = HashMap::new();

    // for every PID in /proc
    let process_dir_paths = read_dir("/proc")?;
    for maybe_path in process_dir_paths {
        let path = maybe_path?;
        if path.file_type()?.is_dir() {
            let path_str = path
                .file_name()
                .into_string()
                .or(Err(Box::new(OsStringConvertError {})))?;
            let pid = path_str.parse::<i32>();
            let Ok(pid) = pid else {
                continue;
            };
            let pid = Pid::from_raw(pid);

            let Ok(fd_paths) = read_dir(format!("/proc/{}/fd", pid)) else {
                continue;
            };
            let Ok(sockets) = describe_open_sockets(pid) else {
                continue;
            };

            // for every FD in this PID
            for maybe_fd_path in fd_paths {
                let fd_path = maybe_fd_path?;
                let fd_str = fd_path
                    .file_name()
                    .into_string()
                    .or(Err(Box::new(OsStringConvertError {})))?;
                let Ok(fd) = fd_str.parse::<u64>() else {
                    continue;
                };
                let maybe_fd = describe_fd(pid, fd);
                // if the fd is a socket, add it to our map
                if maybe_fd.is_some() && maybe_fd.unwrap().fd_type == FdType::Socket {
                    match sockets.iter().find(|s| s.inode == maybe_fd.unwrap().inode) {
                        Some(sock) => drop(open_sockets.insert(sock.local_ip, *sock)),
                        _ => (),
                    }
                }
            }
        }
    }
    Ok(open_sockets)
}

pub fn describe_open_sockets(pid: Pid) -> Result<Vec<Socket>, Box<dyn Error>> {
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
