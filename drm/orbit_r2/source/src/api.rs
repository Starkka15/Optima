#![allow(dead_code)]
#![allow(unused_variables)]

use std::fs::OpenOptions;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::{ptr, slice};

use anyhow::Result;
use cxxabi::cxxabi;
use fnlog::fn_debug;
use log::error;
use once_cell::sync::Lazy;
use thiscall::get_this_ptr_cxx;
use ustr::Ustr;
use widestring::{U16CStr, U16CString};

use crate::global::CONFIG;
use crate::helpers::alloc::alloc;
use crate::helpers::manifest::{read_manifest, write_manifest};
use crate::helpers::save::{get_save_path, get_saves, read_save, remove_save, write_save};
use crate::models::manifest::Save;
use crate::types::{
    IGetLoginDetailsListener, IGetSavegameListListener, IGetSavegameReaderListener,
    IGetSavegameWriterListener, IRemoveSavegameListener, ISavegameReadListener,
    ISavegameWriteListener, OrbitClient, SavegameInfo, SavegameReader, SavegameWriter,
};

static ACCOUNT_ID: Lazy<Ustr> = Lazy::new(|| Ustr::from(&CONFIG.orbit.profile.account_id.as_str()));
static USERNAME: Lazy<Ustr> = Lazy::new(|| Ustr::from(&CONFIG.orbit.profile.username.as_str()));
static PASSWORD: Lazy<Ustr> = Lazy::new(|| Ustr::from(&CONFIG.orbit.profile.password.as_str()));

// Invoke a C++ __thiscall listener method: `this` in ecx, stack args pushed
// right-to-left, callee cleans the stack. CRITICAL: ecx (this) is set in the SAME
// asm block as the `call`, AFTER the args are pushed — the previous approach set
// ecx via a separate `set_this_ptr_cxx()` function whose value was clobbered by
// the compiler's argument setup before the call ever happened, so the game's
// listener ran with this=null and crashed (AC3SP.exe+0x43FA6, write to null+0x230).
// `func` is the method address (read from the listener's vtable slot by the caller).
#[inline(never)]
unsafe fn thiscall_invoke2(this: u32, func: u32, a1: u32, a2: u32) {
    std::arch::asm!(
        "push {a2}",
        "push {a1}",
        "mov ecx, {this}",
        "call {func}",
        this = in(reg) this,
        func = in(reg) func,
        a1 = in(reg) a1,
        a2 = in(reg) a2,
        clobber_abi("C"),
    );
}

#[inline(never)]
unsafe fn thiscall_invoke3(this: u32, func: u32, a1: u32, a2: u32, a3: u32) {
    std::arch::asm!(
        "push {a3}",
        "push {a2}",
        "push {a1}",
        "mov ecx, {this}",
        "call {func}",
        this = in(reg) this,
        func = in(reg) func,
        a1 = in(reg) a1,
        a2 = in(reg) a2,
        a3 = in(reg) a3,
        clobber_abi("C"),
    );
}

#[inline(never)]
unsafe fn thiscall_invoke4(this: u32, func: u32, a1: u32, a2: u32, a3: u32, a4: u32) {
    std::arch::asm!(
        "push {a4}",
        "push {a3}",
        "push {a2}",
        "push {a1}",
        "mov ecx, {this}",
        "call {func}",
        this = in(reg) this,
        func = in(reg) func,
        a1 = in(reg) a1,
        a2 = in(reg) a2,
        a3 = in(reg) a3,
        a4 = in(reg) a4,
        clobber_abi("C"),
    );
}

/// Read the method address from a listener's first slot (its vtable pointer →
/// first virtual method). The emu's listener structs store `callback` as
/// `*const extern "stdcall" fn(..)`; the actual code address is the value at that
/// pointer.
#[inline(always)]
unsafe fn vtable_func<T>(callback: *const T) -> u32 {
    *(callback as *const u32)
}

// --- Asynchronous listener delivery ---------------------------------------
// The Orbit listener APIs (GetSavegameList, GetLoginDetails, ...) are ASYNC by
// contract: the game calls them, they return immediately, and the listener
// callback is invoked LATER from the game's `Update()` pump (main thread). The
// upstream emu invoked the callback synchronously from inside the API call,
// reentering the game before it had finished setting up the manager that the
// callback touches — AC3 null-virtual-calls its savegame manager and crashes at
// AC3SP.exe+0x43FA6 (write to null+0x230). We honor the real contract instead:
// queue the delivery and fire it from `Update()`. Same thread throughout (the
// `thiscall!` this-ptr lives in TLS), so a thread-local queue is correct and
// needs no Send bound on the captured raw pointers.
thread_local! {
    static PENDING: std::cell::RefCell<std::collections::VecDeque<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(std::collections::VecDeque::new());
}

fn defer<F: FnOnce() + 'static>(f: F) {
    PENDING.with(|p| p.borrow_mut().push_back(Box::new(f)));
}

/// Fire every queued listener delivery in order. Called from `Update()`.
fn drain_pending() {
    loop {
        let next = PENDING.with(|p| p.borrow_mut().pop_front());
        match next {
            Some(f) => f(),
            None => break,
        }
    }
}

#[inline(never)]
#[cxxabi(name = "??0OrbitClient@orbitclient@mg@@QAE@XZ", ctor = true)]
fn orbit_client_ctor() -> *const OrbitClient {
    fn_debug!("__CALL__");
    alloc(OrbitClient::default())
}

#[inline(never)]
#[cxxabi(
    name = "?StartProcess@OrbitClient@orbitclient@mg@@QAEXPAG00@Z",
    ctor = false
)]
fn orbit_client_start_process(
    client: *const OrbitClient,
    unk0: *const u16,
    unk1: *const u16,
    unk2: *const u16,
) {
    fn_debug!("__CALL__");
}

#[inline(never)]
#[cxxabi(
    name = "?StartLauncher@OrbitClient@orbitclient@mg@@QAE_NIIPBD0@Z",
    ctor = false
)]
fn orbit_client_start_launcher(
    client: *const OrbitClient,
    unk0: u32,
    unk1: u32,
    unk2: *const c_char,
    unk3: *const c_char,
) -> bool {
    fn_debug!("__CALL__");
    // MUST stay false. Returning true makes AC3 believe the Ubisoft launcher will
    // (re)start the game, so it exits immediately expecting a relaunch that never
    // comes (clean exit, no window). false = run standalone (offline), which is
    // what we want. The later crash is in the savegame/login flow, not here.
    return false;
}

#[inline(never)]
#[cxxabi(
    name = "?GetSavegameList@OrbitClient@orbitclient@mg@@QAEXIPAVIGetSavegameListListener@23@I@Z",
    ctor = false
)]
fn orbit_client_get_savegame_list(
    client: *mut OrbitClient,
    request_id: u32,
    savegame_list_listener_callback: *const IGetSavegameListListener,
    product_id: u32,
) {
    fn_debug!("__CALL__");

    let callback = unsafe { (*savegame_list_listener_callback).callback };

    if callback.is_null() {
        return;
    }

    let result = || -> Result<Vec<Box<SavegameInfo>>> {
        let saves = get_saves()?;
        let mut save_info_list = Vec::new();

        for (id, name, size) in saves {
            let size = size as u32;
            let u16name = U16CString::from_str(name)?;

            save_info_list.push(Box::new(SavegameInfo {
                id,
                size,
                name: u16name,
            }));
        }

        Ok(save_info_list)
    }();

    match result {
        Ok(list) => {
            // Deliver from Update(), not inline — see the async-delivery note above.
            // `list` moves into the closure so the SavegameInfo pointers stay alive
            // until the callback fires; as_ptr() is taken at fire time.
            let listener = savegame_list_listener_callback;
            defer(move || unsafe {
                let func = vtable_func(callback);
                let size = list.len() as u32;
                if size == 0 {
                    thiscall_invoke3(listener as u32, func, request_id, 0, 0);
                } else {
                    let saves = list.as_ptr();
                    thiscall_invoke3(listener as u32, func, request_id, saves as u32, size);
                }
            });
        }
        Err(err) => error!("{}", err),
    }
}

#[inline(never)]
#[cxxabi(
    name = "?GetSavegameWriter@OrbitClient@orbitclient@mg@@QAEXIPAVIGetSavegameWriterListener@23@II_N@Z",
    ctor = false
)]
fn orbit_client_get_savegame_writer(
    client: *mut OrbitClient,
    request_id: u32,
    savegame_writer_listener_callback: *const IGetSavegameWriterListener,
    product_id: u32,
    save_game_id: u32,
    open: bool,
) {
    fn_debug!("__CALL__");

    let callback = unsafe { (*savegame_writer_listener_callback).callback };

    if callback.is_null() {
        return;
    }

    let result = (|| -> Result<PathBuf> {
        let path = get_save_path(save_game_id)?;
        Ok(path)
    })();

    match result {
        Ok(file) => unsafe {
            let client = &mut (*client);
            let options = if open {
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .to_owned()
            } else {
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .to_owned()
            };
            let writer = Box::new(SavegameWriter::new(save_game_id, file, options));

            client.savegame_writer = writer;

            let func = vtable_func(callback);
            let w = client.savegame_writer.as_ref() as *const SavegameWriter as u32;
            thiscall_invoke3(savegame_writer_listener_callback as u32, func, request_id, 0, w);
        },
        Err(err) => error!("{}", err),
    }
}

#[inline(never)]
#[cxxabi(
    name = "?GetSavegameReader@OrbitClient@orbitclient@mg@@QAEXIPAVIGetSavegameReaderListener@23@II@Z",
    ctor = false
)]
fn orbit_client_get_savegame_reader(
    client: *mut OrbitClient,
    request_id: u32,
    savegame_reader_listener_callback: *const IGetSavegameReaderListener,
    product_id: u32,
    save_game_id: u32,
) {
    fn_debug!("__CALL__");

    let callback = unsafe { (*savegame_reader_listener_callback).callback };

    if callback.is_null() {
        return;
    }

    let result = (|| -> Result<PathBuf> {
        let path = get_save_path(save_game_id)?;
        Ok(path)
    })();

    match result {
        Ok(file) => unsafe {
            let client = &mut (*client);
            let reader = Box::new(SavegameReader::new(file));

            client.savegame_reader = reader;

            let func = vtable_func(callback);
            let r = client.savegame_reader.as_ref() as *const SavegameReader as u32;
            thiscall_invoke3(savegame_reader_listener_callback as u32, func, request_id, 0, r);
        },
        Err(err) => error!("{}", err),
    }
}

#[inline(never)]
#[cxxabi(
    name = "?RemoveSavegame@OrbitClient@orbitclient@mg@@QAEXIPAVIRemoveSavegameListener@23@II@Z",
    ctor = false
)]
fn orbit_client_remove_savegame(
    client: *const OrbitClient,
    request_id: u32,
    remove_savegame_listener_callback: *const IRemoveSavegameListener,
    product_id: u32,
    save_game_id: u32,
) {
    fn_debug!("__CALL__");

    let callback = unsafe { (*remove_savegame_listener_callback).callback };

    if callback.is_null() {
        return;
    }

    let result = (|| -> Result<()> {
        remove_save(save_game_id)?;
        Ok(())
    })();

    match result {
        Ok(_) => unsafe {
            let func = vtable_func(callback);
            thiscall_invoke2(remove_savegame_listener_callback as u32, func, request_id, 1);
        },
        Err(err) => error!("{}", err),
    }
}

#[inline(never)]
#[cxxabi(
    name = "?GetLoginDetails@OrbitClient@orbitclient@mg@@QAEXIPAVIGetLoginDetailsListener@23@@Z",
    ctor = false
)]
fn orbit_client_get_login_details(
    client: *const OrbitClient,
    request_id: u32,
    login_details_listener_callback: *const IGetLoginDetailsListener,
) {
    fn_debug!("__CALL__");

    let callback = unsafe { (*login_details_listener_callback).callback };

    if callback.is_null() {
        return;
    }

    // The interned (Ustr) strings are 'static, so the pointers stay valid until
    // the deferred delivery fires from Update().
    let account_id = ACCOUNT_ID.as_ptr();
    let username = USERNAME.as_ptr();
    let password = PASSWORD.as_ptr();
    let listener = login_details_listener_callback;
    defer(move || unsafe {
        let func = vtable_func(callback);
        thiscall_invoke4(
            listener as u32,
            func,
            request_id,
            account_id as u32,
            username as u32,
            password as u32,
        );
    });
}

#[inline(never)]
#[cxxabi(
    name = "?GetRequestUniqueId@OrbitClient@orbitclient@mg@@QAEIXZ",
    ctor = false
)]
fn orbit_client_get_request_unique_id(client: *mut OrbitClient) -> u32 {
    fn_debug!("__CALL__");

    unsafe {
        return (*client).get_next_request_id();
    }
}

#[inline(never)]
#[cxxabi(
    name = "?GetInstallationErrorNum@OrbitClient@orbitclient@mg@@QAEIXZ",
    ctor = false
)]
fn orbit_client_get_installation_error_string(client: *const OrbitClient) -> u16 {
    fn_debug!("__CALL__");
    return 0;
}

#[inline(never)]
#[cxxabi(
    name = "?GetInstallationErrorString@OrbitClient@orbitclient@mg@@QAEPAGPBD@Z",
    ctor = false
)]
fn orbit_client_get_installation_error_num(client: *const OrbitClient) -> *const u16 {
    fn_debug!("__CALL__");
    return ptr::null();
}

#[inline(never)]
#[cxxabi(name = "?Update@OrbitClient@orbitclient@mg@@QAEXXZ", ctor = false)]
fn orbit_client_update(client: *const OrbitClient) {
    fn_debug!("__CALL__");
    // Fire any queued async listener deliveries on the game's pump thread.
    drain_pending();
}

#[inline(never)]
#[cxxabi(name = "??1OrbitClient@orbitclient@mg@@QAE@XZ", ctor = false)]
fn orbit_client_dtor(client: *mut OrbitClient) {
    fn_debug!("__CALL__");

    unsafe {
        Box::from_raw(client);
    }
}

#[inline(never)]
#[cxxabi(
    name = "?GetSavegameId@SavegameInfo@orbitclient@mg@@QAEIXZ",
    ctor = false
)]
fn savegame_info_get_savegame_id(save_game_info: *const Box<SavegameInfo>) -> u32 {
    fn_debug!("__CALL__");

    unsafe {
        return (*save_game_info).id;
    }
}

#[inline(never)]
#[cxxabi(name = "?GetSize@SavegameInfo@orbitclient@mg@@QAEIXZ", ctor = false)]
fn savegame_info_get_size(save_game_info: *const Box<SavegameInfo>) -> u32 {
    fn_debug!("__CALL__");

    unsafe {
        return (*save_game_info).size;
    }
}

#[inline(never)]
#[cxxabi(name = "?GetName@SavegameInfo@orbitclient@mg@@QAEPBGXZ", ctor = false)]
fn savegame_info_get_name(save_game_info: *const Box<SavegameInfo>) -> *const u16 {
    fn_debug!("{:#?}", unsafe { &(*save_game_info) });

    unsafe {
        return (*save_game_info).name.as_ptr();
    }
}

#[inline(never)]
#[cxxabi(
    name = "?Read@SavegameReader@orbitclient@mg@@QAEXIPAVISavegameReadListener@23@IPAXI@Z",
    ctor = false
)]
fn savegame_reader_read(
    save_game_reader: *const SavegameReader,
    request_id: u32,
    savegame_read_listener_callback: *const ISavegameReadListener,
    offset: u32,
    buffer: *mut c_char,
    number_of_bytes: u32,
) {
    fn_debug!("{:#?}", unsafe { &(*save_game_reader) });

    let callback = unsafe { (*savegame_read_listener_callback).callback };

    if callback.is_null() {
        return;
    }

    let reader = unsafe { &(*save_game_reader) };

    let result = (|| -> Result<(Vec<u8>, usize)> {
        let (data, size) = read_save(&reader.path, number_of_bytes as usize, offset as u64)?;
        Ok((data, size))
    })();

    match result {
        Ok((data, size)) => unsafe {
            ptr::copy(data.as_ptr() as *const c_char, buffer, size);

            let func = vtable_func(callback);
            thiscall_invoke2(savegame_read_listener_callback as u32, func, request_id, size as u32);
        },
        Err(err) => error!("{}", err),
    }
}

#[inline(never)]
#[cxxabi(name = "?Close@SavegameReader@orbitclient@mg@@QAEXXZ", ctor = false)]
fn savegame_reader_close(save_game_reader: *const SavegameReader) {
    fn_debug!("__CALL__");
}

#[inline(never)]
#[cxxabi(
    name = "?Write@SavegameWriter@orbitclient@mg@@QAEXIPAVISavegameWriteListener@23@PAXI@Z",
    ctor = false
)]
fn savegame_writer_write(
    save_game_writer: *const SavegameWriter,
    request_id: u32,
    savegame_write_listener_callback: *const ISavegameWriteListener,
    buffer: *const c_char,
    number_of_bytes: u32,
) {
    fn_debug!("{:#?}", unsafe { &(*save_game_writer) });

    let callback = unsafe { (*savegame_write_listener_callback).callback };

    if callback.is_null() {
        return;
    }

    let writer = unsafe { &(*save_game_writer) };

    let result = (|| -> Result<()> {
        let buffer =
            unsafe { slice::from_raw_parts(buffer as *const u8, number_of_bytes as usize) };
        let _ = write_save(&writer.path, &writer.options, buffer)?;
        Ok(())
    })();

    match result {
        Ok(_) => unsafe {
            let func = vtable_func(callback);
            thiscall_invoke2(savegame_write_listener_callback as u32, func, request_id, number_of_bytes as u32);
        },
        Err(err) => error!("{}", err),
    }
}

#[inline(never)]
#[cxxabi(
    name = "?SetName@SavegameWriter@orbitclient@mg@@QAE_NPAG@Z",
    ctor = false
)]
fn savegame_writer_set_name(save_game_writer: *const SavegameWriter, name: *const u16) -> bool {
    fn_debug!("{:#?}", unsafe { &(*save_game_writer) });

    let writer = unsafe { &(*save_game_writer) };

    let result = (|| -> Result<()> {
        let u16str = unsafe { U16CStr::from_ptr_str(name) };
        let u16name = u16str.to_string()?;

        let mut manifest = read_manifest().unwrap_or_default();

        match manifest.saves.iter_mut().find(|save| save.id == writer.id) {
            Some(save) => {
                save.name = u16name;
            }
            None => manifest.saves.push(Save {
                id: writer.id,
                name: u16name,
            }),
        }

        let _ = write_manifest(&manifest)?;
        Ok(())
    })();

    match result {
        Ok(_) => return true,
        Err(err) => error!("{}", err),
    }

    return false;
}

#[inline(never)]
#[cxxabi(name = "?Close@SavegameWriter@orbitclient@mg@@QAEX_N@Z", ctor = false)]
fn savegame_writer_close(save_game_writer: *const SavegameWriter) {
    fn_debug!("__CALL__");
}
