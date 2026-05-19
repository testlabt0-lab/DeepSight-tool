use iced_x86::{Decoder, DecoderOptions, Instruction};

pub struct Disassembler;

impl Disassembler {
    /// Determines how many whole instructions exist within a given minimum byte length.
    /// This is crucial for inline hooking to avoid cutting an instruction in half.
    /// Returns the exact byte length of the instructions that cover at least `min_length` bytes,
    /// and the original instructions themselves.
    pub fn get_instruction_boundaries(
        code: &[u8],
        base_address: u64,
        min_length: usize,
    ) -> Result<(usize, Vec<Instruction>), String> {
        let mut decoder = Decoder::with_ip(64, code, base_address, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        let mut total_length = 0;

        while total_length < min_length {
            if !decoder.can_decode() {
                return Err("Failed to decode enough instructions".to_string());
            }

            let instr = decoder.decode();
            if instr.is_invalid() {
                return Err(format!("Encountered invalid instruction at offset {}", total_length));
            }

            total_length += instr.len();
            instructions.push(instr);
        }

        Ok((total_length, instructions))
    }
}
