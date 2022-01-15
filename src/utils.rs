use std::borrow::Cow;
use std::io::{Cursor, Read, Result, Seek, SeekFrom};
use std::fmt::Write;
use crate::rar::Rar5ReaderState;
use crate::zip::ZipReaderState;

pub fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub enum ProcessingResult {
    Rar5(Rar5ReaderState),
    Zip(ZipReaderState),
}

pub fn arch_index(x: u64) -> u32 {
    x as u8 as u32
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

pub trait ReadHelper<T> where T: AsRef<[u8]> {
    fn read_u8(&mut self) -> Result<u8>;
    fn read_u16(&mut self) -> Result<u16>;
    fn read_u32(&mut self) -> Result<u32>;
    fn read_u64(&mut self) -> Result<u64>;
    fn read_u8_eq(&mut self, value: &u8) -> Result<bool>;
}

impl<T> ReadHelper<T> for Cursor<T> where T: AsRef<[u8]> {
    fn read_u8(&mut self) -> Result<u8> {
        let mut buffer = [0u8; 1];
        self.read_exact(&mut buffer)?;
        Ok(u8::from_le_bytes(buffer))
    }

    fn read_u16(&mut self) -> Result<u16> {
        let mut buffer = [0u8; 2];
        self.read_exact(&mut buffer)?;
        Ok(u16::from_le_bytes(buffer))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let mut buffer = [0u8; 4];
        self.read_exact(&mut buffer)?;
        Ok(u32::from_le_bytes(buffer))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let mut buffer = [0u8; 8];
        self.read_exact(&mut buffer)?;
        Ok(u64::from_le_bytes(buffer))
    }

    fn read_u8_eq(&mut self, value: &u8) -> Result<bool> {
        let read = self.read_u8()?;
        return if value.eq(&read) {
            Ok(true)
        } else {
            self.seek(SeekFrom::Current(-1))?;
            Ok(false)
        }
    }
}