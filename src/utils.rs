use std::borrow::Cow;
use std::io::{Cursor, Read, Result};
use std::fmt::Write;
use crate::rar::Rar5ReaderState;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub enum ProcessingResult {
    Rar5(Rar5ReaderState),
    Zip,
}

pub fn basename(path: &str, sep: char) -> Cow<str> {
    let mut pieces = path.rsplit(sep);
    match pieces.next() {
        Some(p) => p.into(),
        None => path.into(),
    }
}

pub fn read_u8(cursor: &mut Cursor<Vec<u8>>) -> Result<u8> {
    let mut buffer = [0u8; 1];
    cursor.read_exact(&mut buffer)?;
    Ok(u8::from_le_bytes(buffer))
}

pub fn read_le_u32(cursor: &mut Cursor<Vec<u8>>) -> Result<u32> {
    let mut buffer = [0u8; 4];
    cursor.read_exact(&mut buffer)?;
    Ok(u32::from_le_bytes(buffer))
}

pub fn bytes_to_hex(bytes: &[u8]) -> Result<String> {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{:02x}", byte).map_err(|e| std::io::Error::new(std::io::ErrorKind::WriteZero, e))?;
    }

    Ok(result)
}

pub fn read_var_int(cursor: &mut Cursor<Vec<u8>>) -> Result<(u64, u64)> {
    let mut c = [0u8; 1];
    let mut shift = 0;
    let mut accum: u64;

    let mut n = 0u64;

    for i in 0..10 {
        cursor.read(&mut c)?;
        accum = c[0] as u64 & 0x7f;
        n = n + (accum << shift);
        shift += 7;
        if (c[0] & 0x80) == 0 {
            return Ok((n, i + 1));
        }
        c = [0u8; 1];
    }

    return Ok((0, 0));
}