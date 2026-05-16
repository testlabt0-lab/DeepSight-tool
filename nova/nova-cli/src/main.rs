use clap::Parser;
use nova_core::process::Process;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The PID of the process to attach to
    #[arg(short, long)]
    pid: i32,
}

fn main() {
    let args = Args::parse();

    println!("Attaching to process {}", args.pid);

    let process = Process::new(args.pid);

    match process.attach() {
        Ok(_) => {
            println!("Successfully attached to PID {}", args.pid);

            // Try reading the first few bytes of the process's code segment or similar.
            // For now, we don't know where the memory map is, so we'll just read
            // a small chunk at an arbitrary low address (like the ELF header start 0x400000 on many x86_64 systems)
            // Note: This might fail if the address is not mapped.
            let test_addr = 0x400000;
            println!("Attempting to read memory at {:#x}", test_addr);
            match process.read_memory(test_addr, 16) {
                Ok(data) => {
                    print!("Data: ");
                    for b in data {
                        print!("{:02x} ", b);
                    }
                    println!();
                }
                Err(e) => {
                    println!("Failed to read memory (expected if address is unmapped): {}", e);
                }
            }

            println!("Detaching...");
            if let Err(e) = process.detach() {
                eprintln!("Error detaching: {}", e);
            } else {
                println!("Detached successfully.");
            }
        }
        Err(e) => {
            eprintln!("Error attaching to process: {}", e);
        }
    }
}
