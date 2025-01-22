use libc::{c_int, c_void, calloc, free, size_t, strdup, memcpy};

use std::ffi::{CStr, CString};
use std::mem;

use crate::{ffi::pam_conv, PamMessage, PamMessageStyle, PamResponse, PamReturnCode};

/// A trait representing the PAM authentification conversation
///
/// PAM authentification is done as a conversation mechanism, in which PAM
/// asks several questions and the client (your code) answers them. This trait
/// is a representation of such a conversation, which one method for each message
/// PAM can send you.
///
/// This is the trait to implement if you want to customize the conversation with
/// PAM. If you just want a simple login/password authentication, you can use the
/// `PasswordConv` implementation provided by this crate.
pub trait Conversation {
    /// PAM requests a value that should be echoed to the user as they type it
    ///
    /// This would typically be the username. The exact question is provided as the
    /// `msg` argument if you wish to display it to your user.
    fn prompt_echo(&mut self, msg: &CStr) -> Result<CString, ()>;
    /// PAM requests a value that should be typed blindly by the user
    ///
    /// This would typically be the password. The exact question is provided as the
    /// `msg` argument if you wish to display it to your user.
    fn prompt_blind(&mut self, msg: &CStr) -> Result<CString, ()>;
    /// This is an informational message from PAM
    fn info(&mut self, msg: &CStr);
    /// This is an error message from PAM
    fn error(&mut self, msg: &CStr);
    // This is the binary prompt from Linux-PAM
    fn prompt_binary(&mut self, msg: &CStr) -> Result<*mut i8, ()>;
}

/// A minimalistic conversation handler, that uses given login and password
///
/// This conversation handler is not really interactive, but simply returns to
/// PAM the value that have been set using the `set_credentials` method.
pub struct PasswordConv {
    login: String,
    passwd: String,
}

impl PasswordConv {
    /// Create a new `PasswordConv` handler
    pub(crate) fn new() -> PasswordConv {
        PasswordConv {
            login: String::new(),
            passwd: String::new(),
        }
    }

    /// Set the credentials that this handler will provide to PAM
    pub fn set_credentials<U: Into<String>, V: Into<String>>(&mut self, login: U, password: V) {
        self.login = login.into();
        self.passwd = password.into();
    }
}

impl Conversation for PasswordConv {
    fn prompt_echo(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.login.clone()).map_err(|_| ())
    }
    fn prompt_blind(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.passwd.clone()).map_err(|_| ())
    }
    fn info(&mut self, _msg: &CStr) {}
    fn error(&mut self, msg: &CStr) {
        eprintln!("[PAM ERROR] {}", msg.to_string_lossy());
    }
    fn prompt_binary(&mut self, msg: &CStr) -> Result<*mut i8, ()> {
        // Print the binary message and echo it back
        println!("Binary message: {:?}", msg);
        Ok(msg.as_ptr() as *mut i8) 
    }
}

pub(crate) fn into_pam_conv<C: Conversation>(conv: &mut C) -> pam_conv {
    pam_conv {
        conv: Some(converse::<C>),
        appdata_ptr: conv as *mut C as *mut c_void,
    }
}

// FIXME: verify this
pub(crate) unsafe extern "C" fn converse<C: Conversation>(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    out_resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    // allocate space for responses
    let resp =
        calloc(num_msg as usize, mem::size_of::<PamResponse>() as size_t) as *mut PamResponse;
    if resp.is_null() {
        return PamReturnCode::Buf_Err as c_int;
    }

    let handler = &mut *(appdata_ptr as *mut C);

    let mut result: PamReturnCode = PamReturnCode::Success;
    for i in 0..num_msg as isize {
        // get indexed values
        // FIXME: check this
        let m: &mut PamMessage = &mut *(*(msg.offset(i)) as *mut PamMessage);
        let r: &mut PamResponse = &mut *(resp.offset(i));

        let msg = CStr::from_ptr(m.msg);
        // match on msg_style
        match PamMessageStyle::from(m.msg_style) {
            PamMessageStyle::Prompt_Echo_On => {
                if let Ok(handler_response) = handler.prompt_echo(msg) {
                    r.resp = strdup(handler_response.as_ptr());
                } else {
                    result = PamReturnCode::Conv_Err;
                }
            }
            PamMessageStyle::Prompt_Echo_Off => {
                if let Ok(handler_response) = handler.prompt_blind(msg) {
                    r.resp = strdup(handler_response.as_ptr());
                } else {
                    result = PamReturnCode::Conv_Err;
                }
            }
            PamMessageStyle::Text_Info => {
                handler.info(msg);
            }
            PamMessageStyle::Error_Msg => {
                handler.error(msg);
                result = PamReturnCode::Conv_Err;
            }
            PamMessageStyle::Binary_Prompt => {
                if let Ok(handler_response) = handler.prompt_binary(msg) {
                    let size = 88; // This is a hardcoded value for the size of the binary msg
                    r.resp = calloc(size, std::mem::size_of::<*mut u8>()) as *mut i8;
                    if resp.is_null() {
                        return PamReturnCode::Buf_Err as c_int;
                    }
                    let dst_ptr: *mut c_void = r.resp as *mut c_void;
                    let src_ptr: *mut c_void = handler_response as *mut c_void;
                    memcpy(dst_ptr, src_ptr, size);
                } else {
                    result = PamReturnCode::Conv_Err;
                }
            }
        }
        if result != PamReturnCode::Success {
            break;
        }
    }

    // free allocated memory if an error occured
    if result != PamReturnCode::Success {
        free(resp as *mut c_void);
    } else {
        *out_resp = resp;
    }

    result as c_int
}
