use clap::Parser;
use nix::unistd::Pid;
use std::collections::HashSet;

mod proc_fs;
mod unistd_64;
mod interrogate;

use proc_fs::*;
use interrogate::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // PID of the process to investigate
    #[arg(short)]
    pid: i32,
}

fn print_process_state(process_state: &ProcessState) {
    match process_state {
        ProcessState::Running => print!("is Running unblocked"),
        ProcessState::BlockedOnOtherSyscall(syscall) => print!("is blocked on system call {:?}", syscall),
        ProcessState::BlockedOnRegularFileRead(info) => print!("is blocked reading from file {}", info.file_path),
        ProcessState::BlockedOnSocketRead(info) => {
            if let Some(owning_pid) = info.owning_pid {
                print!("is blocked reading from a socket connected to {}, which is served locally by process {}", info.remote_ip, owning_pid)
            } else {
                print!("is blocked reading from a socket connected to {}, which is served on a remote machine", info.remote_ip)
            }
        }
        ProcessState::BlockedOnClosedSocket(fd) => print!("is blocked on a socket that no longer exists (fd {})", fd)
    }
    println!();
}

fn main() {
    let args = Args::parse();
    let pid = Pid::from_raw(args.pid);
    let mut previously_interrogated_pids = HashSet::new();
    let addr_to_socket =
        describe_all_open_sockets().expect("could not read global socket information from /proc");

    let tids = get_thread_ids_for_pid(pid).unwrap_or(vec![]);
    
    // we want to format non-multithreaded outputs differently 
    if tids.len() <= 1 {
        let process_state = interrogate_pid_for_block(pid, pid, &addr_to_socket, &mut previously_interrogated_pids);
        print!("Process {} ", pid.as_raw());
        print_process_state(&process_state);
    } else {
        println!("Process {} is multithreaded.", pid.as_raw());
        for tid in tids {
            let process_state = interrogate_pid_for_block(pid, tid, &addr_to_socket, &mut previously_interrogated_pids);
            print!("\tThread {} ", tid.as_raw());
            print_process_state(&process_state);
        }
    }
}
