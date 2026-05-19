use crate::disasm::Disassembler;
use crate::process::Process;
use crate::remote::RemoteExecution;

pub struct HookEngine<'a> {
    process: &'a Process,
    remote: RemoteExecution<'a>,
}

impl<'a> HookEngine<'a> {
    pub fn new(process: &'a Process) -> Self {
        Self {
            process,
            remote: RemoteExecution::new(process),
        }
    }

    /// Basic inline hook:
    /// 1. Decodes instructions at `target_addr` to find a boundary >= 12 bytes (for an absolute JMP).
    /// 2. Allocates memory for the trampoline.
    /// 3. Writes the original instructions to the trampoline.
    /// 4. Appends a JMP from the trampoline back to the target function (after the overwritten prologue).
    /// 5. Writes the `JMP hook_addr` to the target function.
    pub fn create_inline_hook(&self, target_addr: usize, hook_addr: usize) -> Result<usize, String> {
        // Read 32 bytes from target (usually enough for a prologue)
        let prologue_code = self.process.read_memory(target_addr, 32)?;

        // We need 12 bytes for mov r11, addr; jmp r11
        // Or 14 bytes for jmp [rip+0]; addr
        let min_hook_len = 14;

        let (stolen_len, _instructions) = Disassembler::get_instruction_boundaries(&prologue_code, target_addr as u64, min_hook_len)?;

        // Ensure we don't try to hook something too small
        if stolen_len < min_hook_len {
            return Err("Could not find suitable instruction boundary for hooking".to_string());
        }

        // Allocate memory for the trampoline
        // Size: stolen bytes + 14 bytes for JMP back
        let trampoline_addr = self.remote.allocate_memory(4096)?; // Page size is safe

        // Prepare trampoline code
        let mut trampoline_code = prologue_code[0..stolen_len].to_vec();

        // Append JMP back to target_addr + stolen_len
        let return_addr = target_addr + stolen_len;
        trampoline_code.extend_from_slice(&self.create_absolute_jmp(return_addr));

        // Write trampoline
        self.process.write_memory(trampoline_addr, &trampoline_code)?;

        // Prepare hook JMP
        let mut hook_code = self.create_absolute_jmp(hook_addr);

        // Pad the rest of the stolen bytes with NOPs
        for _ in 0..(stolen_len - hook_code.len()) {
            hook_code.push(0x90);
        }

        // Need to change memory protection if we are using ptrace write directly,
        // but process_vm_writev bypasses memory protection usually if running as root!
        // Alternatively, use ptrace write.
        self.process.write_memory_ptrace(target_addr, &hook_code)?;

        Ok(trampoline_addr)
    }

    /// Generates an absolute JMP instruction (14 bytes)
    /// jmp [rip+0]
    /// <8 byte address>
    fn create_absolute_jmp(&self, addr: usize) -> Vec<u8> {
        let mut jmp = vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
        jmp.extend_from_slice(&(addr as u64).to_ne_bytes());
        jmp
    }
}
