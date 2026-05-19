use crate::process::Process;
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use libc::{c_void, PROT_READ, PROT_WRITE, PROT_EXEC, MAP_PRIVATE, MAP_ANONYMOUS};

pub struct RemoteExecution<'a> {
    process: &'a Process,
}

impl<'a> RemoteExecution<'a> {
    pub fn new(process: &'a Process) -> Self {
        Self { process }
    }

    /// Allocates memory in the target process.
    /// This is a simplified approach: we inject a syscall instruction (`syscall`),
    /// setup the registers to call `mmap`, step over it, and restore the state.
    pub fn allocate_memory(&self, size: usize) -> Result<usize, String> {
        let pid = self.process.pid();
        let nix_pid = nix::unistd::Pid::from_raw(pid);

        // 1. Save original registers
        let orig_regs = ptrace::getregs(nix_pid)
            .map_err(|e| format!("Failed to get registers: {}", e))?;

        // 2. Find an executable region to temporarily write our syscall instruction
        // In a real stealth tool, we'd find an existing `syscall` instruction via scanning
        // to avoid writing to memory, but for now we write it to the current RIP.
        let rip = orig_regs.rip;

        // Save original instructions at RIP
        let orig_code = self.process.read_memory_ptrace(rip as usize, 2)?;

        // Write 'syscall' (0x0f 0x05)
        let syscall_insn = [0x0fu8, 0x05u8];
        self.process.write_memory_ptrace(rip as usize, &syscall_insn)?;

        // 3. Setup registers for mmap syscall
        // mmap(addr, length, prot, flags, fd, offset)
        // System V AMD64 ABI: rdi, rsi, rdx, r10, r8, r9, rax = syscall number
        let mut mmap_regs = orig_regs.clone();
        mmap_regs.rax = libc::SYS_mmap as u64; // Syscall number for mmap (9)
        mmap_regs.rdi = 0; // addr (let OS choose)
        mmap_regs.rsi = size as u64; // length
        mmap_regs.rdx = (PROT_READ | PROT_WRITE | PROT_EXEC) as u64; // prot
        mmap_regs.r10 = (MAP_PRIVATE | MAP_ANONYMOUS) as u64; // flags
        mmap_regs.r8 = !0; // fd (-1)
        mmap_regs.r9 = 0; // offset
        mmap_regs.rip = rip; // Ensure we are at the syscall

        ptrace::setregs(nix_pid, mmap_regs)
            .map_err(|e| format!("Failed to set mmap registers: {}", e))?;

        // 4. Single step to execute the syscall
        ptrace::step(nix_pid, None).map_err(|e| format!("Failed to step: {}", e))?;
        waitpid(nix_pid, None).map_err(|e| format!("Waitpid failed after step: {}", e))?;

        // 5. Get the result (address allocated is in RAX)
        let result_regs = ptrace::getregs(nix_pid)
            .map_err(|e| format!("Failed to get result registers: {}", e))?;

        let allocated_addr = result_regs.rax;

        // 6. Restore original state
        self.process.write_memory_ptrace(rip as usize, &orig_code)?;
        ptrace::setregs(nix_pid, orig_regs)
            .map_err(|e| format!("Failed to restore original registers: {}", e))?;

        // Basic check if mmap failed (returns MAP_FAILED which is usually -1 / 0xffffffffffffffff)
        // Usually, an address mapped in user space on Linux won't be in the very high canonical range
        // unless it's an error. We treat anything above 0xfffffffffffff000 as an error.
        if allocated_addr > 0xfffffffffffff000 {
            return Err(format!("mmap syscall failed, returned error code: {}", allocated_addr as i64));
        }

        Ok(allocated_addr as usize)
    }
}
