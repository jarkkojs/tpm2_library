// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use tpm2_protocol::{TpmBuild, TpmErrorKind, TpmParse, TpmResult, TpmWriter, TPM_MAX_COMMAND_SIZE};

/// A stack of TPM objects
#[derive(Default)]
pub struct TpmStack {
    stack: Vec<Vec<u8>>,
}

impl TpmStack {
    /// Creates a new empty `TpmStack`.
    #[must_use]
    pub fn new() -> Self {
        TpmStack { stack: Vec::new() }
    }

    /// Pushes a TPM object onto the stack.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` on failure.
    pub fn push<T: TpmBuild>(&mut self, obj: &T) -> TpmResult<()> {
        let mut buffer = [0u8; TPM_MAX_COMMAND_SIZE];
        let mut tpm_writer = TpmWriter::new(&mut buffer);

        obj.build(&mut tpm_writer)?;

        let written_len = tpm_writer.len();
        let written_bytes = &buffer[..written_len];
        self.stack.push(written_bytes.to_vec());

        Ok(())
    }

    /// Pops a TPM object from the stack.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` on failure.
    pub fn pop<T: for<'a> TpmParse<'a>>(&mut self) -> TpmResult<T> {
        let bytes = self.stack.pop().ok_or(TpmErrorKind::Boundary)?;

        let (obj, remainder) = T::parse(&bytes)?;

        if !remainder.is_empty() {
            return Err(TpmErrorKind::TrailingData);
        }

        Ok(obj)
    }
}

pub struct TpmStackIterator {
    stack: Vec<Vec<u8>>,
}

impl Iterator for TpmStackIterator {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        self.stack.pop()
    }
}

impl IntoIterator for TpmStack {
    type Item = Vec<u8>;
    type IntoIter = TpmStackIterator;

    fn into_iter(self) -> Self::IntoIter {
        TpmStackIterator { stack: self.stack }
    }
}
