//! A C API over openmls_frb's `MlsEngine` for a process that decrypts for the
//! app while it is not running, e.g. the iOS notification service.
//!
//! It only ever applies application messages, and only through
//! `MlsEngine::process_message_stashed`: the plaintext is kept in the same
//! transaction that deletes its key, for the app to store and delete. Commits
//! and proposals are left for the app, which has to apply them in order before
//! anything that follows them in their group, so the caller stops at them.
//!
//! Every function blocks. Out pointers are only written on success, bytes and
//! strings handed out are released with `openmls_push_free_bytes` and
//! `openmls_push_free_string`.

use std::ffi::{CStr, CString, c_char};
use std::ptr;

use futures::executor::block_on;
use openmls_frb::api::credential::MlsCredential;
use openmls_frb::api::engine::{
    MlsEngine, StashedMessage, mls_message_content_type, mls_message_extract_group_id,
};

pub struct OpenmlsPush {
    engine: MlsEngine,
}

/// The application message was stashed now.
pub const OPENMLS_PUSH_STASHED: i32 = 0;
/// A commit or proposal, nothing was changed.
pub const OPENMLS_PUSH_NOT_APPLICATION: i32 = 1;
/// Nothing was changed, the error says why.
pub const OPENMLS_PUSH_ERROR: i32 = -1;
/// The application message was stashed by an earlier call.
pub const OPENMLS_PUSH_ALREADY_STASHED: i32 = 2;

/// # Safety
/// `err` is null or writable.
unsafe fn set_error(err: *mut *mut c_char, message: String) {
    if err.is_null() {
        return;
    }
    let message = CString::new(message.replace('\0', " ")).unwrap_or_default();
    unsafe { *err = message.into_raw() };
}

/// # Safety
/// `out` and `out_len` are null or writable.
unsafe fn set_bytes(out: *mut *mut u8, out_len: *mut usize, bytes: Vec<u8>) {
    if out.is_null() || out_len.is_null() {
        return;
    }
    let boxed = bytes.into_boxed_slice();
    unsafe {
        *out_len = boxed.len();
        *out = Box::into_raw(boxed).cast::<u8>();
    }
}

/// Opens the engine's database, null on failure. The app's engine holds it
/// while it runs, which fails this after a five second wait.
///
/// # Safety
/// `db_path` is a NUL-terminated string, `key` points to `key_len` bytes and
/// `err` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openmls_push_open(
    db_path: *const c_char,
    key: *const u8,
    key_len: usize,
    err: *mut *mut c_char,
) -> *mut OpenmlsPush {
    if db_path.is_null() || key.is_null() {
        unsafe { set_error(err, "db_path and key are required".into()) };
        return ptr::null_mut();
    }
    let db_path = match unsafe { CStr::from_ptr(db_path) }.to_str() {
        Ok(path) => path.to_owned(),
        Err(e) => {
            unsafe { set_error(err, format!("db_path is not UTF-8: {e}")) };
            return ptr::null_mut();
        }
    };
    let key = unsafe { std::slice::from_raw_parts(key, key_len) }.to_vec();
    match block_on(MlsEngine::create(db_path, key)) {
        Ok(engine) => Box::into_raw(Box::new(OpenmlsPush { engine })),
        Err(e) => {
            unsafe { set_error(err, e) };
            ptr::null_mut()
        }
    }
}

/// Closes the database and frees `push`. Null does nothing.
///
/// # Safety
/// `push` came from `openmls_push_open` and is not used after.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openmls_push_close(push: *mut OpenmlsPush) {
    if push.is_null() {
        return;
    }
    let push = unsafe { Box::from_raw(push) };
    let _ = block_on(push.engine.close());
}

/// Writes the id of the group the MLS message `message` is for, which needs
/// nothing but the message. Returns `OPENMLS_PUSH_ERROR` with `err` for what is
/// no MLS group message, e.g. a welcome.
///
/// # Safety
/// `message` points to `message_len` bytes and every out pointer is null or
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openmls_push_group_id(
    message: *const u8,
    message_len: usize,
    group_id: *mut *mut u8,
    group_id_len: *mut usize,
    err: *mut *mut c_char,
) -> i32 {
    if message.is_null() {
        unsafe { set_error(err, "message is required".into()) };
        return OPENMLS_PUSH_ERROR;
    }
    let message = unsafe { std::slice::from_raw_parts(message, message_len) }.to_vec();
    match mls_message_extract_group_id(message) {
        Ok(group) => {
            unsafe { set_bytes(group_id, group_id_len, group) };
            0
        }
        Err(e) => {
            unsafe { set_error(err, e) };
            OPENMLS_PUSH_ERROR
        }
    }
}

/// Applies the MLS message `message` when it is an application message,
/// stashing its plaintext under `stash_id`, the id the app stores it under.
///
/// Returns `OPENMLS_PUSH_STASHED`, or `OPENMLS_PUSH_ALREADY_STASHED` for a
/// message an earlier call stashed, with the plaintext and the identity of
/// the sender's credential, `OPENMLS_PUSH_NOT_APPLICATION` for a commit or
/// proposal, and `OPENMLS_PUSH_ERROR` with `err` otherwise, e.g. for a message
/// the app already applied. The group id is written for all but errors.
///
/// # Safety
/// `push` came from `openmls_push_open`, `message` points to `message_len`
/// bytes, `stash_id` is a NUL-terminated string and every out pointer is null
/// or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openmls_push_receive(
    push: *mut OpenmlsPush,
    message: *const u8,
    message_len: usize,
    stash_id: *const c_char,
    plaintext: *mut *mut u8,
    plaintext_len: *mut usize,
    sender: *mut *mut u8,
    sender_len: *mut usize,
    group_id: *mut *mut u8,
    group_id_len: *mut usize,
    err: *mut *mut c_char,
) -> i32 {
    if push.is_null() || message.is_null() || stash_id.is_null() {
        unsafe { set_error(err, "push, message and stash_id are required".into()) };
        return OPENMLS_PUSH_ERROR;
    }
    let engine = unsafe { &(*push).engine };
    let message = unsafe { std::slice::from_raw_parts(message, message_len) }.to_vec();
    let stash_id = match unsafe { CStr::from_ptr(stash_id) }.to_str() {
        Ok(id) => id.to_owned(),
        Err(e) => {
            unsafe { set_error(err, format!("stash_id is not UTF-8: {e}")) };
            return OPENMLS_PUSH_ERROR;
        }
    };

    match receive(engine, message, stash_id) {
        Ok(Received::Stashed {
            group,
            identity,
            bytes,
            earlier,
        }) => {
            unsafe {
                set_bytes(group_id, group_id_len, group);
                set_bytes(sender, sender_len, identity);
                set_bytes(plaintext, plaintext_len, bytes);
            }
            if earlier {
                OPENMLS_PUSH_ALREADY_STASHED
            } else {
                OPENMLS_PUSH_STASHED
            }
        }
        Ok(Received::NotApplication { group }) => {
            unsafe { set_bytes(group_id, group_id_len, group) };
            OPENMLS_PUSH_NOT_APPLICATION
        }
        Err(e) => {
            unsafe { set_error(err, e) };
            OPENMLS_PUSH_ERROR
        }
    }
}

enum Received {
    Stashed {
        group: Vec<u8>,
        identity: Vec<u8>,
        bytes: Vec<u8>,
        earlier: bool,
    },
    NotApplication {
        group: Vec<u8>,
    },
}

fn receive(engine: &MlsEngine, message: Vec<u8>, stash_id: String) -> Result<Received, String> {
    let group = mls_message_extract_group_id(message.clone())?;
    if let Some(stashed) = block_on(engine.stashed_message(stash_id.clone()))? {
        return stashed_now_or_earlier(group, stashed, true);
    }
    if mls_message_content_type(message.clone())? != "application" {
        return Ok(Received::NotApplication { group });
    }
    block_on(engine.process_message_stashed(group.clone(), message, stash_id.clone()))?;
    // read back for the sender's credential, which the result leaves out
    let stashed = block_on(engine.stashed_message(stash_id))?
        .ok_or("An application message that was not stashed")?;
    stashed_now_or_earlier(group, stashed, false)
}

fn stashed_now_or_earlier(
    group: Vec<u8>,
    stashed: StashedMessage,
    earlier: bool,
) -> Result<Received, String> {
    let identity = MlsCredential::deserialize(stashed.sender_credential)?.identity()?;
    Ok(Received::Stashed {
        group,
        identity,
        bytes: stashed.plaintext,
        earlier,
    })
}

/// # Safety
/// `bytes` and `len` came from this library, the bytes are not used after.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openmls_push_free_bytes(bytes: *mut u8, len: usize) {
    if bytes.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(bytes, len)) });
}

/// # Safety
/// `string` came from this library and is not used after.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openmls_push_free_string(string: *mut c_char) {
    if string.is_null() {
        return;
    }
    drop(unsafe { CString::from_raw(string) });
}
