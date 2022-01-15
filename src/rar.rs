use crate::constants::*;

use std::io::{Cursor, Read, Seek, SeekFrom, Result};
use sha2::{Digest, Sha256};
use core::fmt::Write;
use crate::constants::*;
use crate::utils::ProcessingResult;
use crate::utils::{basename, bytes_to_hex, read_le_u32, read_u8, read_var_int};

type RarCursor = Cursor<Vec<u8>>;

#[derive(Debug)]
pub struct Rar5ReaderState {
    pub encrypted: bool,

    pub psw_check: [u8; SIZE_PSWCHECK as usize],
    pub use_psw_check: bool,

    pub rar5_salt: [u8; SIZE_SALT50 as usize],
    pub rar5_iterations: u8,

    pub found: Vec<String>,

    pub name: String
}

impl Rar5ReaderState {

    pub fn new() -> Self {
        Rar5ReaderState {
            encrypted: false,

            psw_check: [0u8; SIZE_PSWCHECK],
            use_psw_check: false,

            rar5_salt: [0u8; SIZE_SALT50],
            rar5_iterations: 0,

            found: Vec::new(),

            name: String::from("file.rar")
        }
    }

}

pub fn process_file(mut cursor: RarCursor) -> Result<ProcessingResult> {
    let mut marker_block = [0u8; 8];

    cursor.read_exact(&mut marker_block)?;

    if marker_block.eq(&[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]) { // rar 5
        process_rar5(cursor).map(|state| ProcessingResult::Rar5(state))
    } else if marker_block[0..7].eq(&[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]) {
        panic!("rar3 wip");
    } else {
        panic!("Unsupported format!");
    }
}

fn process_rar5(mut cursor: RarCursor) -> Result<Rar5ReaderState> {
    let mut state = Rar5ReaderState::new();

    loop {
        let pos = cursor.position();

        let next = process_rar5_header(&mut state, &mut cursor);
        if let Err(_) = next {
            return Ok(state);
        }
        let next = next.unwrap();

        if next == u64::MAX {
            break;
        }

        cursor.seek(SeekFrom::Start(pos + next))?;
    }

    Ok(state)
}

fn process_rar5_header(state: &mut Rar5ReaderState, cursor: &mut RarCursor) -> Result<u64> {
    let (mut extra_size, mut data_size) = (0, 0);

    if state.encrypted {
        let mut rar5_iv = [0u8; SIZE_INITV];
        cursor.read_exact(&mut rar5_iv)?;
        let rar5_iv_hex = bytes_to_hex(&rar5_iv)?;

        let rar5_salt_hex = bytes_to_hex(&state.rar5_salt)?;
        let rar5_pwc_hex = bytes_to_hex(&state.psw_check)?;

        let result = format!("{}:$rar5${}${}${}${}${}${}", basename(state.name.as_str(), '/'), SIZE_SALT50, rar5_salt_hex, state.rar5_iterations, rar5_iv_hex, SIZE_PSWCHECK, rar5_pwc_hex);
        state.found.push(result.clone());
    }

    let _head_crc = read_le_u32(cursor)?;
    let (block_size, sizeof_vint) = read_var_int(cursor)?;

    let head_size = block_size + 4 + sizeof_vint;

    let header_type = read_u8(cursor)?;
    let (flags, _) = read_var_int(cursor)?;

    if flags & HFL_EXTRA != 0 {
        let (extra_size_read, _) = read_var_int(cursor)?;
        extra_size = extra_size_read;
    }

    if flags & HFL_DATA != 0 {
        let (data_size_read, _) = read_var_int(cursor)?;
        data_size = data_size_read;
    }

    match header_type {
        HEAD_CRYPT => {
            println!("HEAD_CRYPT");
            let mut chksum = [0u8; SIZE_PSWCHECK_CSUM];

            let (crypt_version, _) = read_var_int(cursor)?;
            if crypt_version > CRYPT_VERSION { panic!("Bad crypt version byte") }

            let (enc_flags, _) = read_var_int(cursor)?;
            state.use_psw_check = (enc_flags & CHFL_CRYPT_PSWCHECK) != 0;
            let lg_2count = read_u8(cursor)?;
            if lg_2count > CRYPT5_KDF_LG2_COUNT_MAX { panic!("rar PBKDF2 iteration count too large") }
            state.rar5_iterations = lg_2count;

            cursor.read_exact(&mut state.rar5_salt)?;

            if state.use_psw_check {
                cursor.read_exact(&mut state.psw_check)?;
                cursor.read_exact(&mut chksum)?;

                let digest = Sha256::digest(state.psw_check);
                let sha256ch = digest.as_slice();

                state.use_psw_check = chksum.eq(sha256ch);
            }

            state.encrypted = true;
        },
        HEAD_MAIN => {
            let (arc_flags, _) = read_var_int(cursor)?;
            if arc_flags & MHFL_VOLNUMBER != 0 {
                let (_vol_number, _) = read_var_int(cursor)?;
            }
        },
        HEAD_FILE | HEAD_SERVICE => {
            let (file_flags, _) = read_var_int(cursor)?;
            let _ = read_var_int(cursor)?; // unp_size
            let _ = read_var_int(cursor)?; // file_attr

            if file_flags & FHFL_UTIME != 0 {
                let _ = read_le_u32(cursor)?;
            }

            if file_flags & FHFL_CRC32 != 0 {
                let _ = read_le_u32(cursor)?;
            }

            let _ = read_var_int(cursor)?; // comp_info
            let _ = read_var_int(cursor)?; // host_os
            let (name_size, _) = read_var_int(cursor)?;

            cursor.seek(SeekFrom::Current(name_size as i64))?;

            if extra_size != 0 {
                process_rar5_extra(state, extra_size, header_type, cursor)?;
            }
        },
        HEAD_ENDARC => {
            return Ok(u64::MAX);
        },
        _ => {}
    }

    Ok(head_size + data_size)
}

fn process_rar5_extra(state: &mut Rar5ReaderState, extra_size: u64, header_type: u8, cursor: &mut RarCursor) -> Result<()> {
    let mut bytes_left = extra_size;

    loop {
        let (field_size, len) = read_var_int(cursor)?;
        if len == 0 || len > 3 { panic!("Invalid rar block"); }
        if bytes_left <= len + field_size { return Ok(()); }
        bytes_left -= len;
        bytes_left -= field_size;
        let (_field_type, _) = read_var_int(cursor)?;

        if header_type == HEAD_FILE || header_type == HEAD_SERVICE {
            let _ = read_var_int(cursor)?; // enc_version
            let (flags, _) = read_var_int(cursor)?;

            if flags & FHEXTRA_CRYPT_PSWCHECK == 0 { panic!("Unsupported file (UsePSWCheck is off)"); }

            let lg2_count = read_u8(cursor)?;

            if lg2_count >= CRYPT5_KDF_LG2_COUNT_MAX { panic!("Lg2Count >= CRYPT5_KDF_LG2_COUNT_MAX (problem with file?)"); }

            cursor.read_exact(&mut state.rar5_salt)?;
            let rar5_salt_hex = bytes_to_hex(&state.rar5_salt)?;

            let mut rar5_iv = [0u8; SIZE_INITV];
            cursor.read_exact(&mut rar5_iv)?;
            let rar5_iv_hex = bytes_to_hex(&rar5_iv)?;

            let mut rar5_pwc = [0u8; SIZE_PSWCHECK];
            cursor.read_exact(&mut rar5_pwc)?;
            let rar5_pwc_hex = bytes_to_hex(&rar5_pwc)?;

            let result = format!("{}:$rar5${}${}${}${}${}${}", basename(state.name.as_str(), '/'), SIZE_SALT50, rar5_salt_hex, lg2_count, rar5_iv_hex, SIZE_PSWCHECK, rar5_pwc_hex);
            state.found.push(result.clone());
            //println!("{}", result);
        }
    }
}