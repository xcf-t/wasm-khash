pub const HFL_EXTRA: u64 = 1;
pub const HFL_DATA: u64 = 2;

pub const CRYPT_VERSION: u64 = 0;
pub const CHFL_CRYPT_PSWCHECK: u64 = 1;
pub const CRYPT5_KDF_LG2_COUNT: u64 = 15;
pub const CRYPT5_KDF_LG2_COUNT_MAX: u8 = 24;
pub const SIZE_SALT50: usize = 16;
pub const SIZE_PSWCHECK: usize = 8;
pub const SIZE_PSWCHECK_CSUM: usize = 4;
pub const SIZE_INITV: usize = 16;

pub const HEAD_MARK: u8 = 0x00;
pub const HEAD_MAIN: u8 = 0x01;
pub const HEAD_FILE: u8 = 0x02;
pub const HEAD_SERVICE: u8 = 0x03;
pub const HEAD_CRYPT: u8 = 0x04;
pub const HEAD_ENDARC: u8 = 0x05;
pub const HEAD_UNKNOWN: u8 = 0xff;

pub const MHFL_VOLUME: u64 = 0x0001;
pub const MHFL_VOLNUMBER: u64 = 0x0002;
pub const MHFL_SOLID: u64 = 0x0004;
pub const MHFL_PROTECT: u64 = 0x0008;
pub const MHFL_LOCK: u64 = 0x0010;

pub const FHFL_DIRECTORY: u64 = 0x0001;
pub const FHFL_UTIME: u64 = 0x0002;
pub const FHFL_CRC32: u64 = 0x0004;
pub const FHFL_UNPUNKNOWN: u64 = 0x0008;

// File and service header extra field values.;
pub const FHEXTRA_CRYPT: u64 = 0x01;
pub const FHEXTRA_HASH: u64 = 0x02;
pub const FHEXTRA_HTIME: u64 = 0x03;
pub const FHEXTRA_VERSION: u64 = 0x04;
pub const FHEXTRA_REDIR: u64 = 0x05;
pub const FHEXTRA_UOWNER: u64 = 0x06;
pub const FHEXTRA_SUBDATA: u64 = 0x07;

// Flags for FHEXTRA_CRYPT.;
pub const FHEXTRA_CRYPT_PSWCHECK: u64 = 0x01;
pub const FHEXTRA_CRYPT_HASHMAC: u64 = 0x02;

pub const FLAG_LOCAL_SIZE_UNKNOWN: u16 = 8;

pub const HEXCHARS_LC: [char; 16] = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];

pub const AES_AUTHENTICATION_CODE_LENGTH: u64 = 10;
pub const AES_PASSWORD_VERIFICATION_LENGTH: u64 = 2;