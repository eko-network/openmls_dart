use std::ffi::{CStr, CString, c_char};
use std::ptr;

use futures::executor::block_on;
use openmls_frb::api::config::MlsGroupConfig;
use openmls_frb::api::engine::MlsEngine;
use openmls_frb::api::keys::MlsSignatureKeyPair;
use openmls_frb::api::types::MlsCiphersuite;
use openmls_push::*;

const SUITE: MlsCiphersuite = MlsCiphersuite::Mls128DhkemX25519Aes128gcmSha256Ed25519;

struct Member {
    engine: MlsEngine,
    signer: Vec<u8>,
    public: Vec<u8>,
    identity: Vec<u8>,
}

fn member(name: &str, db_path: &str, key: &[u8]) -> Member {
    let pair = MlsSignatureKeyPair::generate(SUITE).unwrap();
    Member {
        engine: block_on(MlsEngine::create(db_path.into(), key.to_vec())).unwrap(),
        signer: openmls_frb::api::keys::serialize_signer(
            SUITE,
            pair.private_key(),
            pair.public_key(),
        )
        .unwrap(),
        public: pair.public_key(),
        identity: name.as_bytes().to_vec(),
    }
}

struct Received {
    rc: i32,
    plaintext: Option<Vec<u8>>,
    sender: Option<Vec<u8>>,
    group: Option<Vec<u8>>,
    err: Option<String>,
}

fn receive(push: *mut OpenmlsPush, message: &[u8], stash_id: &str) -> Received {
    let id = CString::new(stash_id).unwrap();
    let (mut pt, mut pt_len, mut gid, mut gid_len) = (ptr::null_mut(), 0, ptr::null_mut(), 0);
    let (mut sender, mut sender_len) = (ptr::null_mut(), 0);
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        openmls_push_receive(
            push,
            message.as_ptr(),
            message.len(),
            id.as_ptr(),
            &mut pt,
            &mut pt_len,
            &mut sender,
            &mut sender_len,
            &mut gid,
            &mut gid_len,
            &mut err,
        )
    };
    let take = |p: *mut u8, len: usize| {
        (!p.is_null()).then(|| {
            let v = unsafe { std::slice::from_raw_parts(p, len) }.to_vec();
            unsafe { openmls_push_free_bytes(p, len) };
            v
        })
    };
    let err = (!err.is_null()).then(|| {
        let s = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();
        unsafe { openmls_push_free_string(err) };
        s
    });
    Received {
        rc,
        plaintext: take(pt, pt_len),
        sender: take(sender, sender_len),
        group: take(gid, gid_len),
        err,
    }
}

#[test]
fn applies_and_stashes_only_application_messages() {
    let dir = tempfile::tempdir().unwrap();
    let bob_path = dir.path().join("bob.db").to_str().unwrap().to_owned();
    let key = [7u8; 32];
    let alice = member("alice", ":memory:", &[1u8; 32]);
    let bob = member("bob", &bob_path, &key);

    let group = block_on(alice.engine.create_group(
        MlsGroupConfig::default_config(SUITE),
        alice.signer.clone(),
        alice.identity.clone(),
        alice.public.clone(),
        None,
        None,
    ))
    .unwrap()
    .group_id;
    let kp = block_on(bob.engine.create_key_package(
        SUITE,
        bob.signer.clone(),
        bob.identity.clone(),
        bob.public.clone(),
        None,
    ))
    .unwrap();
    let added = block_on(alice.engine.add_members(
        group.clone(),
        alice.signer.clone(),
        vec![kp.key_package_bytes],
    ))
    .unwrap();
    block_on(alice.engine.merge_pending_commit(group.clone())).unwrap();
    block_on(bob.engine.join_group_from_welcome(
        MlsGroupConfig::default_config(SUITE),
        added.welcome,
        None,
        bob.signer.clone(),
    ))
    .unwrap();
    // the app lets go of the database, e.g. while in the background
    block_on(bob.engine.close()).unwrap();

    let path = CString::new(bob_path.clone()).unwrap();
    let mut err = ptr::null_mut();
    let push = unsafe { openmls_push_open(path.as_ptr(), key.as_ptr(), key.len(), &mut err) };
    assert!(!push.is_null());

    let hi = block_on(alice.engine.create_message(
        group.clone(),
        alice.signer.clone(),
        b"hi".to_vec(),
        None,
    ))
    .unwrap()
    .ciphertext;
    let first = receive(push, &hi, "a");
    assert_eq!(first.rc, OPENMLS_PUSH_STASHED);
    assert_eq!(first.plaintext.as_deref(), Some(&b"hi"[..]));
    assert_eq!(first.sender.as_deref(), Some(&b"alice"[..]));
    assert_eq!(first.group.as_deref(), Some(&group[..]));

    // e.g. a second push for the same inbox entry, the key is gone by now
    let again = receive(push, &hi, "a");
    assert_eq!(again.rc, OPENMLS_PUSH_ALREADY_STASHED);
    assert_eq!(again.plaintext.as_deref(), Some(&b"hi"[..]));
    assert_eq!(again.sender.as_deref(), Some(&b"alice"[..]));

    let commit = block_on(
        alice
            .engine
            .self_update(group.clone(), alice.signer.clone()),
    )
    .unwrap()
    .commit;
    let left = receive(push, &commit, "b");
    assert_eq!(left.rc, OPENMLS_PUSH_NOT_APPLICATION);
    assert_eq!(left.group.as_deref(), Some(&group[..]));

    let (mut gid, mut gid_len) = (ptr::null_mut(), 0);
    let rc = unsafe {
        openmls_push_group_id(
            hi.as_ptr(),
            hi.len(),
            &mut gid,
            &mut gid_len,
            ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(gid, gid_len) },
        &group[..]
    );
    unsafe { openmls_push_free_bytes(gid, gid_len) };

    let garbage = receive(push, b"not mls", "c");
    assert_eq!(garbage.rc, OPENMLS_PUSH_ERROR);
    assert!(garbage.err.is_some());

    unsafe { openmls_push_close(push) };

    // the app picks the stash up, and the commit is still for it to apply
    let app = block_on(MlsEngine::create(bob_path, key.to_vec())).unwrap();
    let stashed = block_on(app.stashed_messages()).unwrap();
    assert_eq!(stashed.len(), 1);
    assert_eq!(stashed[0].stash_id, "a");
    let epoch = block_on(app.group_epoch(group.clone())).unwrap();
    block_on(app.process_message(group.clone(), commit)).unwrap();
    assert_eq!(block_on(app.group_epoch(group)).unwrap(), epoch + 1);
}
