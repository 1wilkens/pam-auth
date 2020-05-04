//! Authentication related structure and functions
use std::env;

use crate::{conv, enums::*, functions::*, types::*};

/// Main struct to authenticate a user
///
/// You need to create an instance of it to start an authentication process. If you
/// want a simple password-based authentication, you can use `Authenticator::with_password`,
/// and to the following flow:
///
/// ```no_run
/// use pam::Authenticator;
///
/// let mut authenticator = Authenticator::with_password("system-auth")
///         .expect("Failed to init PAM client.");
/// // Preset the login & password we will use for authentication
/// authenticator.handler_mut().set_credentials("login", "password");
/// // Actually try to authenticate:
/// authenticator.authenticate().expect("Authentication failed!");
/// // Now that we are authenticated, it's possible to open a sesssion:
/// authenticator.open_session().expect("Failed to open a session!");
/// ```
///
/// If you wish to customise the PAM conversation function, you should rather create your
/// authenticator with `Authenticator::with_handler`, providing a struct implementing the
/// `Conversation` trait. You can then mutably access your conversation handler using the
/// `Authenticator::handler_mut` method.
///
/// By default, the `Authenticator` will close any opened session when dropped. If you don't
/// want this, you can change its `close_on_drop` field to `False`.
pub struct Authenticator<'a, C: conv::Conversation> {
    /// Flag indicating whether the Authenticator should close the session on drop
    pub close_on_drop: bool,
    handle: &'a mut PamHandle,
    conversation: Box<C>,
    is_authenticated: bool,
    has_open_session: bool,
    last_code: PamReturnCode,
}

impl<'a> Authenticator<'a, conv::PasswordConv> {
    /// Create a new `Authenticator` with a given service name and a password-based conversation
    pub fn with_password(service: &str) -> PamResult<Authenticator<'a, conv::PasswordConv>> {
        Authenticator::with_handler(service, conv::PasswordConv::new())
    }
}

impl<'a, C: conv::Conversation> Authenticator<'a, C> {
    /// Creates a new Authenticator with a given service name and conversation callback
    pub fn with_handler(service: &str, conversation: C) -> PamResult<Authenticator<'a, C>> {
        let mut conversation = Box::new(conversation);
        let conv = conv::into_pam_conv(&mut *conversation);

        let handle = start(service, None, &conv)?;
        Ok(Authenticator {
            close_on_drop: true,
            handle,
            conversation,
            is_authenticated: false,
            has_open_session: false,
            last_code: PamReturnCode::Success,
        })
    }

    /// Immutable access to the conversation handler of this Authenticator
    pub fn handler(&self) -> &C {
        &*self.conversation
    }

    /// Mutable access to the conversation handler of this Authenticator
    pub fn handler_mut(&mut self) -> &mut C {
        &mut *self.conversation
    }

    /// Perform the authentication with the provided credentials
    pub fn authenticate(&mut self) -> PamResult<()> {
        self.last_code = authenticate(self.handle, PamFlag::None);
        if self.last_code != PamReturnCode::Success {
            // No need to reset here
            return Err(From::from(self.last_code));
        }

        self.is_authenticated = true;

        self.last_code = acct_mgmt(self.handle, PamFlag::None);
        if self.last_code != PamReturnCode::Success {
            // Probably not strictly neccessary but better be sure
            return self.reset();
        }
        Ok(())
    }

    /// Open a session for a previously authenticated user and
    /// initialize the environment appropriately (in PAM and regular enviroment variables).
    pub fn open_session(&mut self) -> PamResult<()> {
        if !self.is_authenticated {
            //TODO: is this the right return code?
            return Err(PamReturnCode::Perm_Denied.into());
        }

        self.last_code = setcred(self.handle, PamFlag::Establish_Cred);
        if self.last_code != PamReturnCode::Success {
            return self.reset();
        }

        self.last_code = open_session(self.handle, PamFlag::None);
        if self.last_code != PamReturnCode::Success {
            return self.reset();
        }

        // Follow openSSH and call pam_setcred before and after open_session
        self.last_code = setcred(self.handle, PamFlag::Reinitialize_Cred);
        if self.last_code != PamReturnCode::Success {
            return self.reset();
        }

        self.has_open_session = true;
        self.initialize_environment()
    }

    // Initialize the client environment with common variables.
    // Currently always called from Authenticator.open_session()
    fn initialize_environment(&mut self) -> PamResult<()> {
        use users::os::unix::UserExt;

        let user = users::get_user_by_name(self.conversation.username()).unwrap_or_else(|| {
            panic!(
                "Could not get user by name: {:?}",
                self.conversation.username()
            )
        });

        // Set some common environment variables
        self.set_env(
            "USER",
            user.name()
                .to_str()
                .expect("Unix usernames should be valid UTF-8"),
        )?;
        self.set_env(
            "LOGNAME",
            user.name()
                .to_str()
                .expect("Unix usernames should be valid UTF-8"),
        )?;
        self.set_env("HOME", user.home_dir().to_str().unwrap())?;
        self.set_env("PWD", user.home_dir().to_str().unwrap())?;
        self.set_env("SHELL", user.shell().to_str().unwrap())?;
        // Note: We don't set PATH here, as this should be the job of `pam_env.so`

        Ok(())
    }

    // Utility function to set an environment variable in PAM and the process
    fn set_env(&mut self, key: &str, value: &str) -> PamResult<()> {
        // Set regular environment variable
        env::set_var(key, value);

        // Set pam environment variable
        if getenv(self.handle, key).is_ok() {
            let name_value = format!("{}={}", key, value);
            putenv(self.handle, &name_value)
        } else {
            Ok(())
        }
    }

    // Utility function to reset the pam handle in case of intermediate errors
    fn reset(&mut self) -> PamResult<()> {
        setcred(self.handle, PamFlag::Delete_Cred);
        self.is_authenticated = false;
        Err(From::from(self.last_code))
    }
}

impl<'a, C: conv::Conversation> Drop for Authenticator<'a, C> {
    fn drop(&mut self) {
        if self.has_open_session && self.close_on_drop {
            close_session(self.handle, PamFlag::None);
        }
        let code = setcred(self.handle, PamFlag::Delete_Cred);
        end(self.handle, code);
    }
}
