//! Restrict secret outputs before any plaintext is written. tempfile already
//! creates Unix files with mode 0600; Windows needs an explicit protected DACL.

#[cfg(not(windows))]
pub fn restrict(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn restrict(path: &std::path::Path) -> std::io::Result<()> {
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT,
                SetNamedSecurityInfoW,
            },
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
            PROTECTED_DACL_SECURITY_INFORMATION,
        },
    };
    // OWNER RIGHTS resolves to the actual file owner, not the token of whoever
    // later opens the file. SYSTEM retains access for ordinary OS operations.
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)(A;;FA;;;SY)\0".encode_utf16().collect();
    let filename: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: all UTF-16 inputs are NUL terminated; descriptor and ACL pointers
    // are produced by Win32 and stay alive until the last SetNamedSecurityInfoW
    // call. LocalFree releases the single allocation on every successful parse.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let mut acl = ptr::null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        let result =
            if GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) == 0 {
                Err(std::io::Error::last_os_error())
            } else if present == 0 || acl.is_null() {
                Err(std::io::Error::other("Private output DACL was absent"))
            } else {
                let code = SetNamedSecurityInfoW(
                    filename.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    acl,
                    ptr::null(),
                );
                if code == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::from_raw_os_error(code as i32))
                }
            };
        LocalFree(descriptor);
        result
    }
}
