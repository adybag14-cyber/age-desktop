//! Only the exact child launched for an operation and its Windows Job Object
//! are controlled here. No process-name searches or global termination calls.
#[cfg(windows)]
pub struct Job(windows_sys::Win32::Foundation::HANDLE);
// Kernel job handles can be used from any thread; the last owner closes it.
#[cfg(windows)]
unsafe impl Send for Job {}
#[cfg(windows)]
unsafe impl Sync for Job {}

#[cfg(windows)]
impl Job {
    pub fn attach(child: &std::process::Child) -> std::io::Result<Self> {
        use std::{mem, os::windows::io::AsRawHandle, ptr};
        use windows_sys::Win32::{Foundation::CloseHandle, System::JobObjects::*};
        // SAFETY: this value owns a new unnamed kernel job; the process handle
        // comes from our Child, before any operation request is sent to it.
        unsafe {
            let handle = CreateJobObjectW(ptr::null(), ptr::null());
            if handle.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                mem::size_of_val(&limits) as u32,
            ) == 0
                || AssignProcessToJobObject(handle, child.as_raw_handle()) == 0
            {
                let error = std::io::Error::last_os_error();
                CloseHandle(handle);
                return Err(error);
            }
            Ok(Self(handle))
        }
    }
    pub fn terminate(&self) {
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0, 1);
        }
    }
}
#[cfg(windows)]
impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(not(windows))]
pub struct Job;
#[cfg(not(windows))]
impl Job {
    pub fn attach(_: &std::process::Child) -> std::io::Result<Self> {
        Ok(Self)
    }
    pub fn terminate(&self) {}
}
