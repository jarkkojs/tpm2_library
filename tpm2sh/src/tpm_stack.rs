// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use tpm2_protocol::{TpmBuild, TpmParse, TpmResult, TpmWriter, TPM_MAX_COMMAND_SIZE};

/// A stack of TPM objects, represented as a raw byte buffer.
#[derive(Default, Debug, Clone)]
pub struct TpmStack {
    stack: Vec<u8>,
}

impl TpmStack {
    /// Creates a `TpmStack` directly from a vector of bytes.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self { stack: bytes }
    }

    /// Validates a byte slice and creates a `TpmStack` from it.
    ///
    /// This function validates that the byte slice consists of a valid sequence
    /// of parsable objects of type `T`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if parsing fails at any point in the sequence.
    pub fn from_bytes<T: for<'a> TpmParse<'a>>(bytes: &[u8]) -> TpmResult<Self> {
        let mut tail = bytes;
        while !tail.is_empty() {
            let (_, next_tail) = T::parse(tail)?;
            tail = next_tail;
        }

        Ok(TpmStack {
            stack: bytes.to_vec(),
        })
    }

    /// Returns the stack as a byte slice.
    #[must_use]
    pub fn to_bytes(&self) -> &[u8] {
        &self.stack
    }

    /// Pushes a TPM object onto the top of the stack.
    ///
    /// The object is serialized, and its byte representation is prepended to the stack.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` on a serialization failure.
    pub fn push<T: TpmBuild>(&mut self, object: &T) -> TpmResult<()> {
        let mut buffer = [0u8; TPM_MAX_COMMAND_SIZE];
        let mut writer = TpmWriter::new(&mut buffer);
        object.build(&mut writer)?;

        let writer_len = writer.len();
        let new_bytes = &buffer[..writer_len];

        self.stack.splice(0..0, new_bytes.iter().cloned());
        Ok(())
    }

    /// Pops a TPM object from the top of the stack.
    ///
    /// The raw bytes are parsed into an object of type `T`, and the consumed
    /// bytes are removed from the stack.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` on a parsing failure.
    pub fn pop<T: for<'a> TpmParse<'a>>(&mut self) -> TpmResult<T> {
        let (object, next_stack) = T::parse(&self.stack)?;

        self.stack = next_stack.to_vec();
        Ok(object)
    }
}
