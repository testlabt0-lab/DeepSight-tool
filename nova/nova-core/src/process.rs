use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

pub struct Process {
    pid: Pid,
}

impl Process {
    pub fn new(pid: i32) -> Self {
        Self {
            pid: Pid::from_raw(pid),
        }
    }

    pub fn attach(&self) -> Result<(), String> {
        ptrace::attach(self.pid).map_err(|e| format!("Failed to attach: {}", e))?;

        match waitpid(self.pid, None) {
            Ok(WaitStatus::Stopped(_, Signal::SIGSTOP)) => Ok(()),
            Ok(status) => Err(format!("Unexpected wait status: {:?}", status)),
            Err(e) => Err(format!("Waitpid failed: {}", e)),
        }
    }

    pub fn detach(&self) -> Result<(), String> {
        ptrace::detach(self.pid, None).map_err(|e| format!("Failed to detach: {}", e))
    }

    pub fn read_memory(&self, addr: usize, len: usize) -> Result<Vec<u8>, String> {
        let mut data = Vec::with_capacity(len);
        let mut current_addr = addr;
        let end_addr = addr + len;

        while current_addr < end_addr {
            let word = ptrace::read(self.pid, current_addr as *mut std::ffi::c_void)
                .map_err(|e| format!("Failed to read memory at {:#x}: {}", current_addr, e))?;

            let bytes = word.to_ne_bytes();
            let remaining = end_addr - current_addr;
            let to_copy = std::cmp::min(bytes.len(), remaining);

            data.extend_from_slice(&bytes[..to_copy]);
            current_addr += std::mem::size_of::<i64>();
        }

        Ok(data)
    }
}
