use crate::process::Process;
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use libc::{PROT_READ, PROT_WRITE, PROT_EXEC, MAP_PRIVATE, MAP_ANONYMOUS};

pub struct RemoteExecution<'a> {
    process: &'a Process,
}

impl<'a> RemoteExecution<'a> {
    pub fn new(process: &'a Process) -> Self {
        Self { process }
    }

    /// Allocates memory in the target process.
    pub fn allocate_memory(&self, size: usize) -> Result<usize, String> {
        let pid = self.process.pid();
        let nix_pid = nix::unistd::Pid::from_raw(pid);

        let orig_regs = ptrace::getregs(nix_pid)
            .map_err(|e| format!("Failed to get registers: {}", e))?;

        // ARCH SPECIFIC: x86_64
        #[cfg(target_arch = "x86_64")]
        {
            let rip = orig_regs.rip;
            let orig_code = self.process.read_memory_ptrace(rip as usize, 2)?;

            let syscall_insn = [0x0fu8, 0x05u8];
            self.process.write_memory_ptrace(rip as usize, &syscall_insn)?;

            let mut mmap_regs = orig_regs.clone();
            mmap_regs.rax = libc::SYS_mmap as u64;
            mmap_regs.rdi = 0;
            mmap_regs.rsi = size as u64;
            mmap_regs.rdx = (PROT_READ | PROT_WRITE | PROT_EXEC) as u64;
            mmap_regs.r10 = (MAP_PRIVATE | MAP_ANONYMOUS) as u64;
            mmap_regs.r8 = !0;
            mmap_regs.r9 = 0;
            mmap_regs.rip = rip;

            ptrace::setregs(nix_pid, mmap_regs)
                .map_err(|e| format!("Failed to set mmap registers: {}", e))?;

            ptrace::step(nix_pid, None).map_err(|e| format!("Failed to step: {}", e))?;
            waitpid(nix_pid, None).map_err(|e| format!("Waitpid failed after step: {}", e))?;

            let result_regs = ptrace::getregs(nix_pid)
                .map_err(|e| format!("Failed to get result registers: {}", e))?;

            let allocated_addr = result_regs.rax;

            self.process.write_memory_ptrace(rip as usize, &orig_code)?;
            ptrace::setregs(nix_pid, orig_regs)
                .map_err(|e| format!("Failed to restore original registers: {}", e))?;

            if allocated_addr > 0xfffffffffffff000 {
                return Err(format!("mmap syscall failed, returned error code: {}", allocated_addr as i64));
            }

            Ok(allocated_addr as usize)
        }

        // ARCH SPECIFIC: aarch64
        #[cfg(target_arch = "aarch64")]
        {
            // ARM64 mmap syscall uses SVC #0
            // This is a placeholder for actual ARM64 implementation
            Err("ARM64 remote allocation not fully implemented yet".to_string())
        }
    }

    /// Injects a shared library (.so) into the target process by forcing it to call `dlopen`.
    pub fn inject_library(&self, library_path: &str, dlopen_addr: usize) -> Result<usize, String> {
        let pid = self.process.pid();
        let nix_pid = nix::unistd::Pid::from_raw(pid);

        let path_with_null = format!("{}\0", library_path);
        let path_bytes = path_with_null.as_bytes();

        let alloc_addr = self.allocate_memory(path_bytes.len())?;
        self.process.write_memory_ptrace(alloc_addr, path_bytes)?;

        let orig_regs = ptrace::getregs(nix_pid)
            .map_err(|e| format!("Failed to get registers: {}", e))?;

        // ARCH SPECIFIC: x86_64
        #[cfg(target_arch = "x86_64")]
        {
            let rip = orig_regs.rip;
            let orig_code = self.process.read_memory_ptrace(rip as usize, 2)?;

            self.process.write_memory_ptrace(rip as usize, &[0xCC])?;

            let mut call_regs = orig_regs.clone();

            let mut rsp = orig_regs.rsp;
            rsp = (rsp - 8) & !0xF;

            rsp -= 8;
            self.process.write_memory_ptrace(rsp as usize, &rip.to_ne_bytes())?;

            call_regs.rdi = alloc_addr as u64;
            call_regs.rsi = 2; // RTLD_NOW
            call_regs.rip = dlopen_addr as u64;
            call_regs.rsp = rsp;

            ptrace::setregs(nix_pid, call_regs)
                .map_err(|e| format!("Failed to set call registers: {}", e))?;

            ptrace::cont(nix_pid, None).map_err(|e| format!("Failed to continue: {}", e))?;

            match waitpid(nix_pid, None) {
                Ok(WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP)) => {},
                Ok(WaitStatus::Stopped(_, sig)) => return Err(format!("Unexpected signal during library injection: {:?}", sig)),
                Ok(status) => return Err(format!("Unexpected wait status: {:?}", status)),
                Err(e) => return Err(format!("Waitpid failed: {}", e)),
            }

            let result_regs = ptrace::getregs(nix_pid)
                .map_err(|e| format!("Failed to get result registers: {}", e))?;
            let handle = result_regs.rax;

            self.process.write_memory_ptrace(rip as usize, &orig_code)?;
            ptrace::setregs(nix_pid, orig_regs)
                .map_err(|e| format!("Failed to restore original registers: {}", e))?;

            if handle == 0 {
                return Err("dlopen returned NULL (failed to load library)".to_string());
            }

            Ok(handle as usize)
        }

        // ARCH SPECIFIC: aarch64
        #[cfg(target_arch = "aarch64")]
        {
            Err("ARM64 library injection not fully implemented yet".to_string())
        }
    }
}
