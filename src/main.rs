use clap::Parser;
use nix::{sys::{ptrace, wait}, unistd::Pid};

/// Simple program to greet a person
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
        },
        _ => panic!("Process {} changed state but not to a stopped state!", pid.as_raw())
    }
}

fn main() {
    let args =  Args::parse();
    let pid = Pid::from_raw(args.pid);
    ptrace::attach(pid).unwrap_or_else(|_| panic!("Could not attach to process {}", args.pid));
    
    execute_after_stopped(pid, || {
        ptrace::syscall(pid, None).unwrap_or_else(|_| panic!("Failed to wait for process {} to issue a syscall", args.pid));
        execute_after_stopped(pid, || {
            match ptrace::getregs(pid) {
                Ok(regs) => match regs.orig_rax {
                    0 => println!("process is waiting for a READ operation on fd: {}", regs.rdi),
                    n => println!("process is waiting for syscall #{}", n),
                },
                Err(errno) => println!("Get registers from process failed with code {}", errno),
            }
        });
    });
    ptrace::detach(pid, None).unwrap_or_else(|_| panic!("Failed to detach from process {}", args.pid));
}
