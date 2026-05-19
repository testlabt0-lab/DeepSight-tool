use clap::{Parser, Subcommand};
use nova_core::process::Process;
use nova_core::memory::get_memory_maps;
use nova_core::scanner::Signature;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Install a hardware breakpoint (stealth hook)
    HwHook {
        #[arg(short, long)]
        pid: i32,
        /// Address to hook
        #[arg(short, long)]
        target: String,
    },
    /// Install an inline hook
    Hook {
        #[arg(short, long)]
        pid: i32,
        /// Address to hook
        #[arg(short, long)]
        target: String,
        /// Address to jump to
        #[arg(short='j', long)]
        hook: String,
    },
    /// Allocate memory in the target process
    Alloc {
        #[arg(short, long)]
        pid: i32,
        /// Size to allocate
        #[arg(short, long)]
        size: usize,
    },
    /// Read memory from a process
    Read {
        #[arg(short, long)]
        pid: i32,
        /// Address to read from (in hex)
        #[arg(short, long)]
        addr: String,
        /// Number of bytes to read
        #[arg(short, long)]
        len: usize,
    },
    /// List memory maps of a process
    Maps {
        #[arg(short, long)]
        pid: i32,
    },
    /// Scan for a signature in a process's memory
    Scan {
        #[arg(short, long)]
        pid: i32,
        /// IDA-style signature (e.g., "48 8B 05 ? ? ? ?")
        #[arg(short, long)]
        sig: String,
    }
}

fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Read { pid, addr, len } => {
            let addr = usize::from_str_radix(addr.trim_start_matches("0x"), 16).expect("Invalid address format");
            let process = Process::new(pid);
            println!("Reading {} bytes from {:#x} in process {}", len, addr, pid);

            // Note: process_vm_readv might not need ptrace attach, but it's safe to do so
            if let Err(e) = process.attach() {
                eprintln!("Warning: Attach failed: {}", e);
            }

            match process.read_memory(addr, len) {
                Ok(data) => {
                    print!("Data: ");
                    for b in data {
                        print!("{:02x} ", b);
                    }
                    println!();
                }
                Err(e) => eprintln!("Read failed: {}", e),
            }

            let _ = process.detach();
        }
        Commands::Maps { pid } => {
            match get_memory_maps(pid) {
                Ok(maps) => {
                    println!("{:>16} - {:>16} {:>4} {:>8} {}", "Start", "End", "Perm", "Offset", "Path");
                    for map in maps {
                        let perms = format!(
                            "{}{}{}{}",
                            if map.permissions.read { "r" } else { "-" },
                            if map.permissions.write { "w" } else { "-" },
                            if map.permissions.execute { "x" } else { "-" },
                            if map.permissions.shared { "s" } else { "p" }
                        );
                        println!("{:016x} - {:016x} {} {:08x} {}", map.start, map.end, perms, map.offset, map.pathname);
                    }
                }
                Err(e) => eprintln!("Failed to get maps: {}", e),
            }
        }
        Commands::HwHook { pid, target } => {
            let target_addr = usize::from_str_radix(target.trim_start_matches("0x"), 16).expect("Invalid target format");
            let process = Process::new(pid);
            if let Err(e) = process.attach() {
                eprintln!("Failed to attach: {}", e);
                return;
            }
            let mut hw_manager = nova_core::hwbp::HwBreakpointManager::new(&process);
            match hw_manager.set_exec_breakpoint(target_addr) {
                Ok(dr) => println!("Hardware hook installed on DR{} at {:#x}", dr, target_addr),
                Err(e) => eprintln!("HW Hook failed: {}", e),
            }
            let _ = process.detach();
        }
        Commands::Hook { pid, target, hook } => {
            let target_addr = usize::from_str_radix(target.trim_start_matches("0x"), 16).expect("Invalid target format");
            let hook_addr = usize::from_str_radix(hook.trim_start_matches("0x"), 16).expect("Invalid hook format");
            let process = Process::new(pid);
            if let Err(e) = process.attach() {
                eprintln!("Failed to attach: {}", e);
                return;
            }
            let hook_engine = nova_core::hook::HookEngine::new(&process);
            match hook_engine.create_inline_hook(target_addr, hook_addr) {
                Ok(trampoline) => println!("Hook installed! Trampoline allocated at {:#x}", trampoline),
                Err(e) => eprintln!("Hook failed: {}", e),
            }
            let _ = process.detach();
        }
        Commands::Alloc { pid, size } => {
            let process = Process::new(pid);
            if let Err(e) = process.attach() {
                eprintln!("Failed to attach: {}", e);
                return;
            }
            let remote = nova_core::remote::RemoteExecution::new(&process);
            match remote.allocate_memory(size) {
                Ok(addr) => println!("Successfully allocated {} bytes at {:#x}", size, addr),
                Err(e) => eprintln!("Allocation failed: {}", e),
            }
            let _ = process.detach();
        }
        Commands::Scan { pid, sig } => {
            let signature = Signature::parse(&sig).expect("Invalid signature format");
            let process = Process::new(pid);

            if let Err(e) = process.attach() {
                eprintln!("Warning: Attach failed: {}", e);
            }

            let maps = get_memory_maps(pid).expect("Failed to get memory maps");
            let mut found = false;

            println!("Scanning for signature: {}", sig);

            for map in maps {
                // Only scan readable segments
                if map.permissions.read && map.pathname != "[vsyscall]" {
                    if let Ok(data) = process.read_memory(map.start, map.size()) {
                        if let Some(offset) = signature.find(&data) {
                            println!("Found signature at {:#x} in {}", map.start + offset, map.pathname);
                            found = true;
                        }
                    }
                }
            }

            if !found {
                println!("Signature not found.");
            }

            let _ = process.detach();
        }
    }
}

// In the CLI we can add a simple command to test allocation

// In the CLI we can add a simple command to test hooking
