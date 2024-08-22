use libc::c_char;
use memchr::memchr;

use std::vec::IntoIter;
use std::ffi::{CStr, OsString};

pub struct PamEnvList {
    inner: IntoIter<(OsString, OsString)>
}

impl Iterator for PamEnvList {
    type Item = (String, String);

    fn next(&mut self) -> Option<(String, String)> {
        self.inner.next().map(|(a, b)| (a.into_string().unwrap(), b.into_string().unwrap()))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl PamEnvList {
    pub(crate) fn from_ptr(ptr: *const *const c_char) -> PamEnvList {
        let mut result = Vec::new();

        unsafe {
            let mut current = ptr;
            if !current.is_null() {
                while !(*current).is_null() {
                    if let Some(key_value) = parse_env_line(CStr::from_ptr(*current).to_bytes()) {
                        result.push(key_value);
                    }
                    current = current.add(1);
                }
            }
        }

        drop_env_list(ptr);
        return PamEnvList { inner: result.into_iter() };
    }
}


fn parse_env_line(input: &[u8]) -> Option<(OsString, OsString)> {
    // Strategy (copied from glibc): Variable name and value are separated
    // by an ASCII equals sign '='. Since a variable name must not be
    // empty, allow variable names starting with an equals sign. Skip all
    // malformed lines.
    use std::os::unix::prelude::OsStringExt;

    if input.is_empty() {
        return None;
    }
    let pos = memchr(b'=', input).map(|p| p + 1);
    pos.map(|p| {
        (
            OsStringExt::from_vec(input[..p].to_vec()),
            OsStringExt::from_vec(input[p + 1..].to_vec()),
        )
    })
}

#[cfg(target_os = "linux")]
fn drop_env_list(ptr: *const *const c_char) {
    unsafe { crate::ffi::pam_misc_drop_env(ptr as *mut *mut c_char) };
}

#[cfg(not(target_os = "linux"))]
fn drop_env_list(ptr: *const *const c_char) {
    // FIXME: verify this
    unsafe {
        let mut cur = *ptr;
        while !cur.is_null() {
            libc::free(cur as *mut libc::c_void);
            cur = cur.add(1);
        }
        libc::free(ptr as *mut libc::c_void);
    }
}
