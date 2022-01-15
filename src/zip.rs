use std::io::{Cursor, ErrorKind, Result, Seek, SeekFrom};
use std::fmt::Write;
use crate::constants::{AES_AUTHENTICATION_CODE_LENGTH, AES_PASSWORD_VERIFICATION_LENGTH, FLAG_LOCAL_SIZE_UNKNOWN, HEXCHARS_LC};
use crate::utils::{arch_index, ReadHelper};
use crate::ProcessingResult;

type ZipCursor = Cursor<Vec<u8>>;

#[derive(Debug)]
pub struct ZipReaderState {
    pub curzip: ZipPTR,
    pub archive: ZipFile,
    pub num_candidates: i32,

    pub file_size: u64,

    pub found: Vec<String>,
    pub debug: Vec<String>,
    pub name: String
}

impl ZipReaderState {
    pub fn new() -> Self {
        ZipReaderState {
            curzip: Default::default(),
            archive: Default::default(),
            num_candidates: 0,
            file_size: 0,
            found: Vec::new(),
            debug: Vec::new(),
            name: String::from("file.zip")
        }
    }
}

#[derive(Debug, Default)]
pub struct ZipFile {
    // imagine an fp here
    filename: String,
    check_bytes: i32,
    zip64: i32,
}

#[derive(Debug, Default)]
pub struct ZipPTR {
    version: u16,
    flags: u16,
    magic_type: u16,
    cmptype: u16,
    hash_data: String,
    file_name: String,
    offset: u64,
    offex: u64,
    cmp_len: u64,
    decomp_len: u64,
    crc: u32,
    cs: [u8; 5],
    zip64: i32,
    lastmod_date: u16,
    lastmod_time: u16,
    extrafield_length: u16,
    aes: ZipAES,
}

#[derive(Debug, Default)]
struct ZipAES {
    found: u16,
    vendor_version: u16,
    vendor_id: u16,
    strength: u8,
    cmptype: u16,
}

pub fn process_file(data: Vec<u8>) -> Result<ProcessingResult> {
    let filesize = data.len() as u64;
    let mut cursor = Cursor::new(data);
    if filesize > 22 + 65536 {
        cursor.seek(SeekFrom::End(-22 - 65535))?;
    } else {
        cursor.seek(SeekFrom::Start(0))?;
    }

    let mut ctx = ZipReaderState::new();

    ctx.file_size = filesize;

    let (mut this_disk, mut cd_start_disk) = (0, 0);
    let (mut num_records, mut num_records_total) = (0u64, 0u64);
    let (mut cd_size, mut cd_start_offset) = (0, 0);

    while cursor.position() < filesize {
        if cursor.read_u8()? == 0x50 && cursor.read_u8_eq(&0x4b)? {
            let mut found = 0;
            let mut zip64 = 0i32;

            if cursor.read_u8_eq(&0x05)? && cursor.read_u8_eq(&0x06)? {
                found = cursor.position();
                this_disk = cursor.read_u16()? as u32;
                cd_start_disk = cursor.read_u16()? as u32;
            } else if cursor.read_u8_eq(&0x06)? && cursor.read_u8_eq(&0x06)? {
                found = cursor.position();
                zip64 = 1;
                cursor.read_u64()?;
                cursor.read_u16()?;
                cursor.read_u16()?;
                this_disk = cursor.read_u32()?;
                cd_start_disk = cursor.read_u32()?;
            }

            if found != 0 {
                if this_disk != 0 || cd_start_disk != 0 {
                    println!("Found EOCD header, but this is either a multipart archive (which are not supported), or false positive");

                    cursor.seek(SeekFrom::Start(found))?;
                } else {
                    ctx.archive.zip64 = zip64;
                    break;
                }
            }
        }
    }

    if cursor.position() >= filesize {
        return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "Did not find End of Central Directory"));
    }

    if ctx.archive.zip64 != 0 {
        num_records = cursor.read_u64()?;
        num_records_total = cursor.read_u64()?;
        cd_size = cursor.read_u64()?;
        cd_start_offset = cursor.read_u64()?;
    } else {
        num_records = cursor.read_u16()? as u64;
        num_records_total = cursor.read_u16()? as u64;
        cd_size = cursor.read_u32()? as u64;
        cd_start_offset = cursor.read_u32()? as u64;
    }

    if num_records != num_records_total {
        println!("num_records != num_records_total");
    }

    cursor.seek(SeekFrom::Start(cd_start_offset))?;

    let cdf_header = cursor.read_u32()?;
    if cdf_header != 0x02014b50 {
        panic!("Did not find a Central Directory File Header at expected file offset");
    }

    while num_records > 0 {
        let id: u32;
        let fn_len: u16;
        let mut extra_len: u16;
        let comment_len: u16;
        let old_pos: i64;

        ctx.curzip = ZipPTR::default();

        num_records -= 1;

        cursor.read_u16()?;

        ctx.curzip.version = cursor.read_u16()? & 0xff;
        ctx.curzip.flags = cursor.read_u16()?;
        ctx.curzip.cmptype = cursor.read_u16()?;

        cursor.read_u16()?; // filemtime
        cursor.read_u16()?; // filemdate

        ctx.curzip.crc = cursor.read_u32()?;
        ctx.curzip.cmp_len = cursor.read_u32()? as u64;
        ctx.curzip.decomp_len = cursor.read_u32()? as u64;
        fn_len = cursor.read_u16()?;
        extra_len = cursor.read_u16()?;
        comment_len = cursor.read_u16()?;

        cursor.read_u16()?; // disk number
        cursor.read_u16()?; // internal attr
        cursor.read_u32()?; // external attr

        ctx.curzip.offset = cursor.read_u32()? as u64;

        let mut buffer = Vec::new();
        let mut fn_count = fn_len as i32;
        while fn_count > 0 {
            buffer.push(cursor.read_u8()?);
            fn_count -= 1;
        }

        ctx.curzip.file_name = String::from_utf8(buffer).unwrap_or(String::from("Unknown"));

        println!("{}", ctx.curzip.file_name);

        while extra_len >= 4 {
            let (efh_id, efh_len) = (cursor.read_u16()?, cursor.read_u16()?);
            extra_len -= 4;

            if efh_id == 0x0001 {
                println!("ZIP64");
                cursor.seek(SeekFrom::Current(efh_len as i64))?;
            } else if efh_id == 0x9901 {
                println!("AES_EF");
                handle_aes_ef(&mut cursor, &mut ctx, efh_len)?;
            } else {
                cursor.seek(SeekFrom::Current(efh_len as i64))?;
            }
            extra_len = extra_len.wrapping_sub(efh_len);
        }

        old_pos = cursor.position() as i64;
        cursor.seek(SeekFrom::Start(ctx.curzip.offset))?;
        id = cursor.read_u32()?;

        if id != 0x04034b50 {
            println!("Did not find local file header for {}", ctx.curzip.file_name);
        } else {
            handle_file_entry(&mut cursor, &mut ctx)?;
        }
    }

    Ok(ProcessingResult::Zip(ctx))
}

fn handle_file_entry(cursor: &mut ZipCursor, ctx: &mut ZipReaderState) -> Result<()> {
    if load_local_header(cursor, ctx)? == 0 {
        return Ok(());
    }

    if ctx.curzip.cmptype == 99 {
        let res = process_aes(cursor, ctx)?;

        if res != 0 {
            return Ok(());
        }

        println!("Skipping bad AES entry");

        return Ok(());
    }

    if ctx.curzip.decomp_len < 4 {
        println!("Skipping short file");
        return Ok(());
    }

    // TODO: legacy

    Ok(())
}

fn handle_aes_ef(cursor: &mut ZipCursor, ctx: &mut ZipReaderState, efh_len: u16) -> Result<()> {
    if efh_len != 7 {
        cursor.seek(SeekFrom::Current(efh_len as i64))?;
        println!("AES_EXTRA_DATA_LENGTH is not 7");
        return Ok(());
    }

    ctx.curzip.aes.found = 1;
    ctx.curzip.aes.vendor_version = cursor.read_u16()?;
    ctx.curzip.aes.vendor_id = cursor.read_u16()?;
    ctx.curzip.aes.strength = cursor.read_u8()?;
    ctx.curzip.aes.cmptype = cursor.read_u16()?;

    Ok(())
}

fn load_local_header(cursor: &mut ZipCursor, ctx: &mut ZipReaderState) -> Result<i32> {
    ctx.curzip.offset = cursor.position() - 4;
    ctx.curzip.version = cursor.read_u16()? & 0xff;
    ctx.curzip.flags = cursor.read_u16()?;
    ctx.curzip.cmptype = cursor.read_u16()?;
    ctx.curzip.lastmod_time = cursor.read_u16()?;
    ctx.curzip.lastmod_date = cursor.read_u16()?;

    if ctx.curzip.flags & FLAG_LOCAL_SIZE_UNKNOWN == 0 { //TODO: != or ==
        let mut crc: u32 = cursor.read_u32()?;
        let mut cmp_len: u32 = cursor.read_u32()?;
        let mut decomp_len: u32 = cursor.read_u32()?;
        if ctx.curzip.zip64 == 0 {
            if crc == 0 && ctx.curzip.crc != 0 {
                panic!("Field mismatch");
            } else {
                ctx.curzip.crc = crc;
            }

            if cmp_len == 0 && ctx.curzip.cmp_len != 0 {
                panic!("Field mismatch");
            } else {
                ctx.curzip.cmp_len = cmp_len as u64;
            }

            if decomp_len == 0 && ctx.curzip.decomp_len != 0 {
                panic!("Field mismatch");
            } else {
                ctx.curzip.decomp_len = decomp_len as u64;
            }
        }

    } else {
        cursor.seek(SeekFrom::Current(12))?;
    }

    let filename_length = cursor.read_u16()?;
    ctx.curzip.extrafield_length = cursor.read_u16()?;

    if !ctx.curzip.file_name.is_empty() {
        cursor.seek(SeekFrom::Current(filename_length as i64))?;
    } else {
        let mut data = Vec::new();
        for _ in 0..filename_length {
            data.push(cursor.read_u8()?);
        }
        ctx.curzip.file_name = String::from_utf8(data).expect("Failed to get filename");
    }

    ctx.curzip.magic_type = 0;
    ctx.curzip.offex = (30 + filename_length + ctx.curzip.extrafield_length) as u64;

    Ok(1)
}

fn process_aes(cursor: &mut ZipCursor, ctx: &mut ZipReaderState) -> Result<i32> {
    let real_cmpr_len: u64;
    let mut efh_id: u16;
    let mut efh_datasize: u16;
    let mut salt_length: u32;
    let mut ef_remaining = ctx.curzip.extrafield_length;

    while ef_remaining > 0 {
        efh_id = cursor.read_u16()?;
        efh_datasize = cursor.read_u16()?;

        ef_remaining = ef_remaining - 2 - 2 - efh_datasize;

        if efh_id == 0x9901 {
            handle_aes_ef(cursor, ctx, efh_datasize)?;
        } else if efh_id == 0x0001 {
            todo!("zip64");
        } else {
            cursor.seek(SeekFrom::Current(efh_datasize as i64))?;
        }
    }

    if ctx.curzip.aes.found == 0 {
        ctx.debug.push("Couldn't find (valid) extra header for type 99 AES entry!".to_string());
        return Ok(0);
    }

    if ctx.curzip.aes.vendor_version < 1 || ctx.curzip.aes.vendor_version > 2 {
        ctx.debug.push("Unknown AES version".to_string());
        return Ok(0);
    }

    if ctx.curzip.aes.strength < 1 || ctx.curzip.aes.strength > 3 {
        ctx.debug.push("Unknown AES strength".to_string());
        return Ok(0);
    }

    if ctx.curzip.aes.vendor_version == 2 && ctx.curzip.crc != 0 {
        ctx.debug.push("ODD: CRC isn't 0 for AE-2 file".to_string());
    }

    if ctx.curzip.cmp_len == 0 && (ctx.curzip.flags & FLAG_LOCAL_SIZE_UNKNOWN == 0) {
        scan_for_data_descriptor(cursor, ctx)?;
    }

    salt_length = 4 + 4 * (ctx.curzip.aes.strength as u32);
    let mut salt = Vec::new();
    for _ in 0..salt_length {
        let b = cursor.read_u8()?;
        salt.push(b);
    }

    let mut result = String::new();

    write!(result, "{}/{}:$zip2$*0*{}*{}*", ctx.name, ctx.curzip.file_name, ctx.curzip.aes.strength, 0).unwrap();

    for i in 0..salt_length {
        write!(result, "{}{}", HEXCHARS_LC[arch_index((salt[i as usize] >> 4) as u64) as usize], HEXCHARS_LC[arch_index((salt[i as usize] & 0x0f) as u64) as usize]).unwrap();
    }
    write!(result, "*").unwrap();
    for _ in 0..2 {
        let d = cursor.read_u8()?;

        write!(result, "{}{}", HEXCHARS_LC[arch_index((d >> 4) as u64) as usize], HEXCHARS_LC[arch_index((d & 0x0f) as u64) as usize]).unwrap();
    }

    if ctx.curzip.cmp_len <= AES_PASSWORD_VERIFICATION_LENGTH + salt_length as u64 + AES_AUTHENTICATION_CODE_LENGTH {
        real_cmpr_len = 0;
        ctx.debug.push("Compressed length of AES entry too short".to_string());
    } else {
        real_cmpr_len = ctx.curzip.cmp_len - AES_PASSWORD_VERIFICATION_LENGTH - salt_length as u64 - AES_AUTHENTICATION_CODE_LENGTH;
    }
    write!(result, "*{:x}*", real_cmpr_len).unwrap();

    if real_cmpr_len > 0x400000000u64 {
        write!(result, "ZFILE*{}*{:x}*{:x}", ctx.curzip.file_name, ctx.curzip.offset, cursor.position()).unwrap();
        cursor.seek(SeekFrom::Current(real_cmpr_len as i64))?;
    } else {
        for _ in 0..real_cmpr_len {
            let d = cursor.read_u8()?;
            write!(result, "{}{}", HEXCHARS_LC[arch_index((d >> 4) as u64) as usize], HEXCHARS_LC[arch_index((d & 0x0f) as u64) as usize]).unwrap();
        }
    }
    write!(result, "*").unwrap();

    for _ in 0..10 {
        let d = cursor.read_u8()?;
        write!(result, "{}{}", HEXCHARS_LC[arch_index((d >> 4) as u64) as usize], HEXCHARS_LC[arch_index((d & 0x0f) as u64) as usize]).unwrap();
    }

    write!(result, "*$/zip2$:{}:{}:{}", ctx.curzip.file_name, ctx.name, ctx.name).unwrap();

    ctx.found.push(result);

    Ok(1)
}

fn scan_for_data_descriptor(cursor: &mut ZipCursor, ctx: &mut ZipReaderState) -> Result<()> {
    let saved_pos = cursor.position();
    let mut crc = 0u32;
    let (mut cmp_len, mut decomp_len) = (0u64, 0u64);


    if ctx.curzip.cmp_len != 0 && ctx.curzip.decomp_len != 0 && ctx.curzip.crc != 0 {
        return Ok(());
    }

    if ctx.curzip.cmp_len == 0 && ctx.curzip.decomp_len == 0 && (ctx.curzip.flags & FLAG_LOCAL_SIZE_UNKNOWN == 0) {
        return Ok(());
    }

    if (ctx.curzip.cmp_len != 0 || ctx.curzip.decomp_len != 0 || ctx.curzip.crc != 0) && (ctx.curzip.flags & FLAG_LOCAL_SIZE_UNKNOWN == 0) {
        return Ok(());
    }

    while cursor.position() < ctx.file_size {
        if cursor.read_u8()? != 0x50 || !cursor.read_u8_eq(&0x4b)? {
            continue;
        }

        if cursor.read_u8_eq(&0x07)? && cursor.read_u8_eq(&0x08)? {
            crc = cursor.read_u32()?;

            if ctx.curzip.zip64 != 0 {
                cmp_len = cursor.read_u64()?;
                decomp_len = cursor.read_u64()?;
            } else {
                cmp_len = cursor.read_u32()? as u64;
                decomp_len = cursor.read_u32()? as u64;
            }
            break;
        }

        if cursor.read_u8_eq(&0x03)? && cursor.read_u8_eq(&0x04)? || cursor.read_u8_eq(&0x01)? && cursor.read_u8_eq(&0x02)? {
            if ctx.curzip.zip64 != 0 {
                cursor.seek(SeekFrom::Current(-24))?;
            } else {
                cursor.seek(SeekFrom::Current(-16))?;
            }

            crc = cursor.read_u32()?;

            if ctx.curzip.zip64 != 0 {
                cmp_len = cursor.read_u64()?;
                decomp_len = cursor.read_u64()?;
            } else {
                cmp_len = cursor.read_u32()? as u64;
                decomp_len = cursor.read_u32()? as u64;
            }
            break;
        }
    }

    if cursor.position() >= ctx.file_size {
        ctx.debug.push("Found nothing".to_string());
    } else {
        if cmp_len > cursor.position() - ctx.curzip.offset {
            ctx.debug.push("Weird edge case".to_string());
        }

        if ctx.curzip.cmp_len == 0 {
            ctx.curzip.cmp_len = cmp_len;
        }

        if ctx.curzip.decomp_len == 0 {
            ctx.curzip.decomp_len = decomp_len;
        }

        if ctx.curzip.crc == 0 {
            ctx.curzip.crc = crc;
        }
    }

    cursor.seek(SeekFrom::Start(saved_pos))?;

    return Ok(());
}