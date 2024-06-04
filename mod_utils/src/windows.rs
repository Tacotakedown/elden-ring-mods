// utils for interfacing with winapi

use std::{ffi::OsStr, os::windows::ffi::OsStrExt};

pub fn to_string_wide(string: &str) -> Vec<u16> {
    OsStr::new(string)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
