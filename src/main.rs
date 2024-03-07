use clap::Parser;
use nix::{
    sys::{ptrace, wait},
    unistd::Pid,
};
use num_traits::FromPrimitive;
use std::collections::HashMap;

mod proc_fs;
mod unistd_64;

use proc_fs::*;
use unistd_64::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // PID of the process to investigate
    #[arg(short)]
    pid: i32,
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

fn interrogate_pid_for_block(pid: Pid, addr_to_socket: &HashMap<SocketAddress, Socket>) {
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
                    // understand the file descriptor details
                    let fd =
                        describe_fd(pid, regs.rdi).expect("Failed to get fd stats for process");
                    println!("process {} is waiting for a Read operation on file descriptor {} which is a {:?}", pid.as_raw(), regs.rdi, fd.fd_type);

                    // if its a socket, handle some special logic
                    match fd.fd_type {
                        FdType::Socket => {
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

                            // see if this is being served by our machine
                            match addr_to_socket.get(&socket.remote_ip) {
                                Some(remote_socket) => {
                                    // run recursively to see why our blocker is blocked
                                    println!(
                                        "that IP is being served on this machine by PID {}",
                                        remote_socket.owning_pid
                                    );
                                    interrogate_pid_for_block(
                                        Pid::from_raw(remote_socket.owning_pid),
                                        addr_to_socket,
                                    );
                                }
                                _ => (),
                            }
                        }
                        FdType::Regular => {
                            let file_path = get_path_of_regular_fd(pid, regs.rdi)
                                .expect("Failed to get path of regular file descriptor");
                            println!("Blocking file is: {}", file_path);
                        }
                        _ => (),
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
    let addr_to_socket =
        describe_all_open_sockets().expect("could not read global socket information from /proc");
    interrogate_pid_for_block(pid, &addr_to_socket);
}
