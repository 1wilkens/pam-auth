//! Wrapped FFI bindings to Linux-PAM
//!
//! Rustified wrappers around the unsafe PAM functions.
//!
//! Note: These wrappers get added as I need them. Feel free to open an issue
//! or PR for the ones that you require which haven't been added yet.

#[cfg(feature = "auth")]
pub use appl::*;

#[cfg(feature = "module")]
pub use modules::*;

pub use types::*;

#[cfg(target_os = "linux")]
pub use misc::*;

/* ------------------------ <security/pam_appl.h> -------------------------- */
#[cfg(feature = "auth")]
mod appl {
    use crate::{PamFlag, PamHandle, PamResult, PamReturnCode};
    use libc::c_int;
    use pam_sys as ffi;
    use std::ffi::CString;

    #[inline]
    pub fn start<'a>(
        service: &str,
        user: Option<&str>,
        conversation: &ffi::pam_conv,
    ) -> PamResult<&'a mut PamHandle> {
        if let Ok(service) = CString::new(service) {
            // Only service is required -> initialize handle
            let mut handle: *mut PamHandle = std::ptr::null_mut();

            let user_ptr = super::try_str_option_to_ptr(user)?;
            match unsafe { ffi::pam_start(service.as_ptr(), user_ptr, conversation, &mut handle) }
                .into()
            {
                // Reborrow is safe, because we check for null before
                PamReturnCode::Success => {
                    assert!(
                        !handle.is_null(),
                        "Got PAM_SUCESS from pam_start but handle is null!"
                    );
                    Ok(unsafe { &mut *handle })
                }
                err => Err(err.into()),
            }
        } else {
            // Invalid service
            super::buffer_error()
        }
    }

    #[inline]
    pub fn end(handle: &mut PamHandle, status: PamReturnCode) -> PamReturnCode {
        // FIXME: Add PAM_DATA_SILENT argument?
        unsafe { ffi::pam_end(handle, status as c_int) }.into()
    }

    #[inline]
    pub fn authenticate(handle: &mut PamHandle, flags: PamFlag) -> PamReturnCode {
        // FIXME: man says, authenticate only accepts PAM_SILENT and PAM_DISALLOW_NULL_AUTHTOK
        unsafe { ffi::pam_authenticate(handle, flags as c_int) }.into()
    }

    #[inline]
    pub fn setcred(handle: &mut PamHandle, flags: PamFlag) -> PamReturnCode {
        // FIXME: man says, setcred only accepts PAM_{ESTABLISH,DELETE,REINITIALIZE,REFRESH}_CRED
        unsafe { ffi::pam_setcred(handle, flags as c_int) }.into()
    }

    #[inline]
    pub fn acct_mgmt(handle: &mut PamHandle, flags: PamFlag) -> PamReturnCode {
        // FIXME: man says, acct_mgmt only accepts PAM_SILENT and PAM_DISALLOW_NULL_AUTHTOK
        unsafe { ffi::pam_acct_mgmt(handle, flags as c_int) }.into()
    }

    #[inline]
    pub fn open_session(handle: &mut PamHandle, flags: PamFlag) -> PamReturnCode {
        // FIXME: Add PAM_SILENT argument?
        unsafe { ffi::pam_open_session(handle, flags as c_int) }.into()
    }

    #[inline]
    pub fn close_session(handle: &mut PamHandle, flags: PamFlag) -> PamReturnCode {
        // FIXME: Add PAM_SILENT argument?
        unsafe { ffi::pam_close_session(handle, flags as c_int) }.into()
    }

    #[inline]
    pub fn chauthtok(handle: &mut PamHandle, flags: PamFlag) -> PamReturnCode {
        // FIXME: man says, chauthtok only accepts PAM_SILENT and PAM_CHANGE_EXPIRED_AUTHTOK
        unsafe { ffi::pam_chauthtok(handle, flags as c_int) }.into()
    }
}
/* ------------------------ <security/pam_appl.h> -------------------------- */

/* ----------------------- <security/_pam_types.h> ------------------------- */
mod types {
    use crate::{PamHandle, PamItemType, PamResult, PamReturnCode};
    use libc::{c_int, c_void};
    use pam_sys as ffi;
    use std::ffi::{CStr, CString};

    #[inline]
    pub fn set_item(
        handle: &mut PamHandle,
        item_type: PamItemType,
        item: &c_void,
    ) -> PamResult<()> {
        match unsafe { ffi::pam_set_item(handle, item_type as c_int, item) }.into() {
            PamReturnCode::Success => Ok(()),
            err => Err(err.into()),
        }
    }

    #[inline]
    pub fn get_item<'a>(handle: &PamHandle, item_type: PamItemType) -> PamResult<&'a c_void> {
        let mut item_ptr: *const c_void = std::ptr::null();
        match unsafe { ffi::pam_get_item(handle, item_type as c_int, &mut item_ptr) }.into() {
            PamReturnCode::Success => {
                assert!(
                    !item_ptr.is_null(),
                    "Got PAM_SUCCESS from pam_get_item, but ptr is null!"
                );
                Ok(unsafe { &*item_ptr })
            }
            err => Err(err.into()),
        }
    }

    #[inline]
    pub fn strerror(handle: &mut PamHandle, errnum: PamReturnCode) -> &str {
        // We don't match here, as man says this function always returns a pointer to a string
        unsafe { CStr::from_ptr(ffi::pam_strerror(handle, errnum as c_int)) }
            .to_str()
            .expect("Got invalid UTF8 string from pam_strerror")
    }

    #[inline]
    pub fn putenv(handle: &mut PamHandle, name_value: &str) -> PamResult<()> {
        if let Ok(name_value) = CString::new(name_value) {
            match unsafe { ffi::pam_putenv(handle, name_value.as_ptr()) }.into() {
                PamReturnCode::Success => Ok(()),
                err => Err(err.into()),
            }
        } else {
            super::buffer_error()
        }
    }

    #[inline]
    pub fn getenv<'a>(handle: &'a mut PamHandle, name: &str) -> PamResult<Option<&'a str>> {
        if let Ok(name) = CString::new(name) {
            // Get environment variable
            let env = unsafe { ffi::pam_getenv(handle, name.as_ptr()) };
            if !env.is_null() {
                // Convert to rust &str
                Ok(Some(
                    unsafe { CStr::from_ptr(env) }
                        .to_str()
                        .expect("Got invalid UTF-8 string from pam_getenv"),
                ))
            } else {
                // This might still be an error, but we don't know for sure
                Ok(None)
            }
        } else {
            super::buffer_error()
        }
    }

    /*#[inline]
    pub fn getenvlist(handle: &mut PamHandle) -> *const *const c_char {
        //TODO: find a convenient way to handle this with Rust types
        unsafe { ffi::pam_getenvlist(handle) }
    }*/
}
/* ----------------------- <security/_pam_types.h> ------------------------- */

/* ----------------------- <security/pam_misc.h> --------------------------- */
// FIXME: Investigate, if pam_misc is supported on any other platform
#[cfg(target_os = "linux")]
mod misc {
    use crate::{PamHandle, PamResult, PamReturnCode};
    use pam_sys as ffi;
    use std::ffi::CString;

    #[inline]
    pub fn misc_paste_env(handle: &mut PamHandle, user_env: &[&str]) -> PamResult<()> {
        // Taken from: https://github.com/rust-lang/rust/issues/9564#issuecomment-95354558
        let user_env: Vec<_> = user_env
            .iter()
            // FIXME: This panics if there are nul-bytes in any string
            .map(|&env| CString::new(env).unwrap())
            .collect();
        let env_ptrs: Vec<_> = user_env
            .iter()
            .map(|env| env.as_ptr())
            .chain(Some(std::ptr::null()))
            .collect();

        match unsafe { ffi::pam_misc_paste_env(handle, env_ptrs.as_ptr()) }.into() {
            PamReturnCode::Success => Ok(()),
            err => Err(err.into()),
        }
    }

    /*#[inline]
    pub fn misc_drop_env(env: &mut *mut c_char) -> PamReturnCode {
        unsafe { ffi::pam_misc_drop_env(env) })
    }*/

    #[inline]
    pub fn misc_setenv(
        handle: &mut PamHandle,
        name: &str,
        value: &str,
        readonly: bool,
    ) -> PamResult<()> {
        if let (Ok(name), Ok(value)) = (CString::new(name), CString::new(value)) {
            let flag = readonly as libc::c_int;
            match unsafe { ffi::pam_misc_setenv(handle, name.as_ptr(), value.as_ptr(), flag) }
                .into()
            {
                PamReturnCode::Success => Ok(()),
                err => Err(err.into()),
            }
        } else {
            super::buffer_error()
        }
    }
}
/* ----------------------- <security/pam_misc.h> --------------------------- */

/* ----------------------- <security/pam_modules.h> ------------------------ */
#[cfg(feature = "module")]
mod modules {
    use crate::{PamHandle, PamResult, PamReturnCode};
    use libc::{c_char, c_int, c_void};
    use pam_sys as ffi;
    use std::ffi::{CStr, CString};

    #[inline]
    pub fn set_data(
        handle: &mut PamHandle,
        module_data_name: &str,
        data: &mut c_void,
        // FIXME: Remove bare ptrs from closure signature
        cleanup: Option<unsafe extern "C" fn(*mut PamHandle, *mut c_void, c_int)>,
    ) -> PamResult<()> {
        if let Ok(module_data_name) = CString::new(module_data_name) {
            match unsafe { ffi::pam_set_data(handle, module_data_name.as_ptr(), data, cleanup) }
                .into()
            {
                PamReturnCode::Success => Ok(()),
                err => Err(err.into()),
            }
        } else {
            super::buffer_error()
        }
    }

    //pub fn get_data(handle: *const PamHandle, module_data_name: *const c_char, data: *const *const c_void);

    #[inline]
    pub fn get_user<'a>(handle: &'a PamHandle, prompt: Option<&str>) -> PamResult<&'a str> {
        // For some reason, bindgen marks the handl as mutable in pam_sys although man says const
        let handle = handle as *const PamHandle as *mut PamHandle;
        let mut user_ptr: *const c_char = std::ptr::null();
        let prompt_ptr = super::try_str_option_to_ptr(prompt)?;

        match unsafe { ffi::pam_get_user(handle, &mut user_ptr, prompt_ptr) }.into() {
            PamReturnCode::Success => {
                assert!(
                    !user_ptr.is_null(),
                    "Got PAM_Success from pam_get_user but ptr is null!"
                );
                Ok(unsafe { CStr::from_ptr(user_ptr) }
                    .to_str()
                    .expect("Got invalid UTF8 string from pam_get_user"))
            }
            err => Err(err.into()),
        }
    }
}
/* ----------------------- <security/pam_modules.h> ------------------------ */

#[inline]
fn buffer_error<T>() -> crate::PamResult<T> {
    Err(crate::PamReturnCode::Buf_Err.into())
}

fn try_str_option_to_ptr(opt: Option<&str>) -> crate::PamResult<*const libc::c_char> {
    match opt.map(std::ffi::CString::new) {
        // Valid string given -> Return ptr of the converted CString
        Some(Ok(content)) => Ok(content.as_ptr()),
        // No string given -> Return null-ptr
        None => Ok(std::ptr::null_mut()),
        // Invalid string given -> Return BUF_ERR
        _ => Err(crate::PamReturnCode::Buf_Err.into()),
    }
}
