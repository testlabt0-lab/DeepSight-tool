use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use nix::sys::uio::{process_vm_readv, process_vm_writev, RemoteIoVec};
use std::io::IoSlice;
use std::io::IoSliceMut;

pub struct Process {
    pid: Pid,
}

impl Process {
    pub fn new(pid: i32) -> Self {
        Self {
            pid: Pid::from_raw(pid),
        }
    }

    pub fn pid(&self) -> i32 {
        self.pid.as_raw()
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

    pub fn read_memory_ptrace(&self, addr: usize, len: usize) -> Result<Vec<u8>, String> {
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
            current_addr += std::mem::size_of::<libc::c_long>();
        }

        Ok(data)
    }

    pub fn read_memory(&self, addr: usize, len: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; len];
        let local_iov = IoSliceMut::new(&mut buf);
        let remote_iov = RemoteIoVec {
            base: addr,
            len,
        };

        match process_vm_readv(self.pid, &mut [local_iov], &[remote_iov]) {
            Ok(bytes_read) if bytes_read == len => Ok(buf),
            Ok(bytes_read) => {
                buf.truncate(bytes_read);
                Ok(buf)
            }
            Err(e) => Err(format!("process_vm_readv failed at {:#x}: {}", addr, e)),
        }
    }

    pub fn write_memory(&self, addr: usize, data: &[u8]) -> Result<usize, String> {
        let local_iov = IoSlice::new(data);
        let remote_iov = RemoteIoVec {
            base: addr,
            len: data.len(),
        };

        process_vm_writev(self.pid, &[local_iov], &[remote_iov])
            .map_err(|e| format!("process_vm_writev failed at {:#x}: {}", addr, e))
    }
}
