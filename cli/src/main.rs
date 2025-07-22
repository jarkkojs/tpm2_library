// SPDX-License-Identifier: GPL-3.0-or-later
#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use clap::{Parser, Subcommand};
use clap_num::maybe_hex;
use log::{debug, error};
use std::{
    fs::{self, File, OpenOptions},
    io::{Error as IoError, ErrorKind, Read, Result as IoResult, Write},
    os::unix::fs::FileTypeExt,
    path::Path,
};
use tpm2_call::{Algorithm, Capability, Command, Response, ResponseCode, Session, Tag, Handle};

/// Status for TPM command execution.
#[derive(Debug, strum_macros::Display, PartialEq)]
pub enum TpmError {
    /// Invalid data was received from the device.
    InvalidData,
    /// A read operation from the device failed.
    InvalidRead,
    /// A write operation to the device failed.
    InvalidWrite,
}

/// Authenticated session nonce size.
const NONCE_SIZE: u16 = 16;

/// Reads and parses a TPM response from a device stream.
fn read_response<T>(file: &mut T) -> Result<Response, TpmError>
where
    T: Read + Write,
{
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).or(Err(TpmError::InvalidRead))?;

    if buf.len() < 10 {
        return Err(TpmError::InvalidData);
    }

    let tag_raw = u16::from_be_bytes([buf[0], buf[1]]);
    let size = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
    let rc_raw = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);

    if size as usize != buf.len() {
        return Err(TpmError::InvalidData);
    }

    let parameters = buf[10..].to_vec();

    Ok(Response {
        tag: Tag::from_repr(tag_raw),
        size,
        rc: ResponseCode::from(rc_raw),
        parameters,
    })
}

fn get_capability<T>(file: &mut T, property: u32, property_count: u32) -> Result<Vec<u32>, TpmError>
where
    T: Read + Write,
{
    let mut cmd = vec![];
    cmd.extend((Tag::NoSessions as u16).to_be_bytes());
    cmd.extend((22_u32).to_be_bytes());
    cmd.extend((Command::GetCapability as u32).to_be_bytes());
    cmd.extend((Capability::Handles as u32).to_be_bytes());
    cmd.extend(property.to_be_bytes());
    cmd.extend(property_count.to_be_bytes());
    file.write_all(&cmd).or(Err(TpmError::InvalidWrite))?;

    let response = read_response(file)?;
    let parameters = response.parameters;

    if parameters.len() < 9 || ((parameters.len() - 9) & 0x03) != 0 {
        return Err(TpmError::InvalidData);
    }

    let handles_count =
        u32::from_be_bytes([parameters[5], parameters[6], parameters[7], parameters[8]]) as usize;
    if handles_count != ((parameters.len() - 9) >> 2) {
        return Err(TpmError::InvalidData);
    }

    if handles_count > property_count as usize {
        return Err(TpmError::InvalidData);
    }

    let mut handles = vec![];
    for i in 0..handles_count {
        let j: usize = 9 + i * 4;
        let handle = u32::from_be_bytes([
            parameters[j],
            parameters[j + 1],
            parameters[j + 2],
            parameters[j + 3],
        ]);
        handles.push(handle);
    }

    Ok(handles)
}

#[allow(dead_code)]
fn start_auth_session<T>(
    file: &mut T,
    session_type: Session,
    nonce_caller: &[u8; NONCE_SIZE as usize],
) -> Result<[u8; NONCE_SIZE as usize], TpmError>
where
    T: Read + Write,
{
    let mut buf = vec![];
    buf.extend((Tag::NoSessions as u16).to_be_bytes());
    buf.extend((43_u32).to_be_bytes());
    buf.extend((Command::StartAuthSession as u32).to_be_bytes());
    buf.extend((Handle::Null as u32).to_be_bytes()); // bind
    buf.extend((Handle::Null as u32).to_be_bytes()); // tpmKey
    buf.extend(NONCE_SIZE.to_be_bytes());
    buf.extend(nonce_caller);
    buf.extend((0_u16).to_be_bytes());
    buf.extend((session_type as u8).to_be_bytes());
    buf.extend((Algorithm::Null as u16).to_be_bytes());
    buf.extend((Algorithm::Sha256 as u16).to_be_bytes());
    file.write_all(&buf).or(Err(TpmError::InvalidWrite))?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf).or(Err(TpmError::InvalidRead))?;
    if buf.len() != 32 {
        return Err(TpmError::InvalidData);
    }

    let mut nonce_tpm = [0; 16];
    nonce_tpm.clone_from_slice(&buf[16..32]);
    Ok(nonce_tpm)
}

struct Device(File);

impl Device {
    pub fn open(path: &str) -> IoResult<Device> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(IoError::from(ErrorKind::InvalidInput));
        }
        let Ok(metadata) = fs::metadata(path) else {
            return Err(IoError::from(ErrorKind::InvalidInput));
        };
        if !metadata.file_type().is_char_device() {
            return Err(IoError::from(ErrorKind::InvalidInput));
        }
        let Ok(path) = std::fs::canonicalize(path) else {
            return Err(IoError::from(ErrorKind::InvalidInput));
        };
        debug!("{}", path.to_str().unwrap());
        Ok(Device(
            OpenOptions::new().read(true).write(true).open(path)?,
        ))
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, default_value = "/dev/tpmrm0")]
    device: String,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Decode response code
    Rc {
        /// Response code
        #[arg(value_parser = maybe_hex::<u32>)]
        rc: u32,
    },
    /// Enumerate objects
    List {
        /// Transient handles
        #[arg(short, long)]
        transient: bool,
        /// Persistent handles
        #[arg(short, long)]
        persistent: bool,
    },
}

const MAX_HANDLES: u32 = 16;

fn main() {
    env_logger::init();
    let cli = Cli::parse();
    match &cli.command {
        Commands::Rc { rc } => {
            println!("{} {rc:#010x}", ResponseCode::from(*rc));
        }
        Commands::List {
            transient,
            persistent,
        } => {
            let mut chip = Device::open(&cli.device).unwrap_or_else(|err| {
                error!("{err}");
                std::process::exit(1);
            });
            if *transient {
                let handles = get_capability(&mut chip.0, Handle::Transient as u32, MAX_HANDLES)
                    .unwrap_or_else(|err| {
                        error!("{err:?}");
                        std::process::exit(1);
                    });
                for handle in handles {
                    println!("{handle:#010x}");
                }
            }
            if *persistent {
                let handles =
                    get_capability(&mut chip.0, Handle::Persistent as u32, MAX_HANDLES)
                        .unwrap_or_else(|err| {
                            error!("{err:?}");
                            std::process::exit(1);
                        });
                for handle in handles {
                    println!("{handle:#010x}");
                }
            }
        }
    }
}
