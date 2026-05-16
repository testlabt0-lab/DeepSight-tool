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
