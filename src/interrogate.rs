use nix::{
    libc::user_regs_struct,
    sys::{ptrace, wait},
    unistd::Pid,
};
use num_traits::FromPrimitive;
use std::collections::HashMap;
use std::{thread, time::Duration};

use crate::proc_fs::*;
use crate::unistd_64::*;

#[derive(Debug, Clone)]
pub enum ProcessState {
    Running,
    BlockedOnRegularFileRead(RegularFileBlockInfo),
    BlockedOnSocketRead(SocketBlockInfo),
    BlockedOnOtherSyscall(SystemCall),
    BlockedOnClosedSocket(u64),
}

#[derive(Debug, Clone)]
pub struct SocketBlockInfo {
    pub fd: u64,
    pub remote_ip: SocketAddress,
    pub owning_pid: Option<Pid>,
}

#[derive(Debug, Clone)]
pub struct RegularFileBlockInfo {
    pub fd: u64,
    pub file_path: String,
}

pub fn wait_for_stop(pid: Pid) {
    match wait::waitpid(pid, None) {
        Ok(wait::WaitStatus::Stopped(_, _)) => (),
        _ => {
            ptrace::detach(pid, None)
                .unwrap_or_else(|_| panic!("Failed to detach from process {}", pid.as_raw()));
            panic!(
                "Process {} changed state but not to a stopped state!",
                pid.as_raw()
            );
        }
    }
}

pub fn check_if_blocked(pid: Pid) -> bool {
    for _ in 0..4 {
        if let Ok(wait::WaitStatus::Stopped(_, _)) =
            wait::waitpid(pid, Some(wait::WaitPidFlag::WNOHANG))
        {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

pub fn analyze_syscall(
    pid: Pid,
    regs: user_regs_struct,
    addr_to_socket: &HashMap<SocketAddress, Socket>,
) -> ProcessState {
    match FromPrimitive::from_u64(regs.orig_rax) {
        Some(SystemCall::Read) | Some(SystemCall::Recvfrom) => {
            // understand the file descriptor details
            let fd = describe_fd(pid, regs.rdi).expect("Failed to get fd stats for process");

            // if its a socket, handle some special logic
            match fd.fd_type {
                FdType::Socket => {
                    let sockets = describe_open_sockets(pid)
                        .expect("failed to describe sockets for the blocked process");
                    let socket = sockets.iter().find(|s| s.inode == fd.inode);

                    if let Some(socket) = socket {
                        // see if this is being served by our machine
                        return match addr_to_socket.get(&socket.remote_ip) {
                            Some(remote_socket) => {
                                ProcessState::BlockedOnSocketRead(SocketBlockInfo {
                                    fd: regs.rdi,
                                    remote_ip: socket.remote_ip,
                                    owning_pid: Some(Pid::from_raw(remote_socket.owning_pid)),
                                })
                            }
                            _ => ProcessState::BlockedOnSocketRead(SocketBlockInfo {
                                fd: regs.rdi,
                                remote_ip: socket.remote_ip,
                                owning_pid: None,
                            }),
                        };
                    } else {
                        ProcessState::BlockedOnClosedSocket(regs.rdi)
                    }
                }
                FdType::Regular => {
                    let file_path = get_path_of_regular_fd(pid, regs.rdi)
                        .expect("Failed to get path of regular file descriptor");
                    ProcessState::BlockedOnRegularFileRead(RegularFileBlockInfo {
                        fd: regs.rdi,
                        file_path,
                    })
                }
                _ => ProcessState::BlockedOnOtherSyscall(SystemCall::Read),
            }
        }
        Some(other) => ProcessState::BlockedOnOtherSyscall(other),
        None => ProcessState::BlockedOnOtherSyscall(
            SystemCall::from_u64(regs.orig_rax)
                .expect("Could not interpret what system call was being issued"),
        ),
    }
}

pub fn interrogate_pid_for_block(
    pid: Pid,
    tid: Pid,
    addr_to_socket: &HashMap<SocketAddress, Socket>,
) -> ProcessState {
    let mut state = ProcessState::Running;
    ptrace::attach(tid).unwrap_or_else(|_| panic!("Could not attach to process {}", tid.as_raw()));
    wait_for_stop(tid);
    ptrace::syscall(tid, None).unwrap_or_else(|_| {
        panic!(
            "Failed to wait for process {} to issue a syscall",
            tid.as_raw()
        )
    });

    if check_if_blocked(tid) {
        match ptrace::getregs(tid) {
            Ok(regs) => state = analyze_syscall(pid, regs, addr_to_socket),
            Err(errno) => panic!("Get registers from process failed with code {}", errno),
        }
    }

    let _ = ptrace::detach(tid, None);
    state
}
