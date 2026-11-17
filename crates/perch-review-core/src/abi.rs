//! The browser builds' interface (target `wasm32v1-none`): the
//! [`crate::envelope`] functions as wasm exports, over an arena allocator,
//! with a panic handler that traps. Two modules are built from it: feature
//! `abi-review` exports `review`, `budget` and `chosen`, what a signing
//! dialog needs; feature `abi-witness` exports `witness`, for a
//! derived-grant view. Each carries only the code its exports reach.
//!
//! A call is `alloc(len)`, writing `len` input bytes at the pointer it
//! returns, then an export with that pointer and length, which returns the
//! output's pointer and length packed as `(ptr << 32) | len`. `alloc` starts
//! a call: it frees everything the previous call allocated, its output
//! included, so the caller copies the output out before the next call. The
//! module imports nothing; its only other export is its memory.

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::arch::wasm32;
use core::cell::Cell;
use core::ptr::null_mut;

const PAGE: usize = 65536;

extern "C" {
    /// The first byte past the data and the stack, which wasm-ld defines.
    static __heap_base: u8;
}

/// A bump allocator over the memory from `__heap_base` on, reset at the
/// start of every call. The wasm has one thread.
struct Arena {
    next: Cell<usize>,
}

// SAFETY: the wasm32v1-none module runs on one thread.
unsafe impl Sync for Arena {}

#[global_allocator]
static ARENA: Arena = Arena { next: Cell::new(0) };

impl Arena {
    fn base() -> usize {
        // Only the symbol's address is taken.
        core::ptr::addr_of!(__heap_base) as usize
    }

    fn reset(&self) {
        self.next.set(Self::base());
    }

    /// Make the memory reach `end`, growing it if needed.
    fn reach(end: usize) -> bool {
        let have = wasm32::memory_size(0) * PAGE;
        end <= have || wasm32::memory_grow(0, (end - have).div_ceil(PAGE)) != usize::MAX
    }
}

// SAFETY: every block is fresh memory below the memory's end, aligned as
// asked; nothing is freed until `reset`, which only `alloc` (the export)
// calls, when no block of the previous call is in use.
unsafe impl GlobalAlloc for Arena {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let next = match self.next.get() {
            0 => Self::base(),
            n => n,
        };
        let Some(start) = next.checked_next_multiple_of(layout.align()) else {
            return null_mut();
        };
        let Some(end) = start.checked_add(layout.size()) else {
            return null_mut();
        };
        if !Self::reach(end) {
            return null_mut();
        }
        self.next.set(end);
        start as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // The newest block grows or shrinks in place.
        if ptr as usize + layout.size() == self.next.get() {
            let Some(end) = (ptr as usize).checked_add(new_size) else {
                return null_mut();
            };
            if !Self::reach(end) {
                return null_mut();
            }
            self.next.set(end);
            return ptr;
        }
        // SAFETY: as `GlobalAlloc::realloc`'s default, by this allocator.
        unsafe {
            let new = self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
            if !new.is_null() {
                core::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
            }
            new
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    wasm32::unreachable()
}

/// Start a call: free the previous call's memory and return room for `len`
/// input bytes.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    ARENA.reset();
    let mut v = Vec::<u8>::with_capacity(len);
    let p = v.as_mut_ptr();
    core::mem::forget(v);
    p
}

#[allow(dead_code)]
fn out(v: Vec<u8>) -> u64 {
    let (p, n) = (v.as_ptr() as u64, v.len() as u64);
    core::mem::forget(v);
    (p << 32) | n
}

/// # Safety
///
/// `ptr` and `len` name the input `alloc` made room for.
#[allow(dead_code)]
unsafe fn input<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    // SAFETY: the caller's.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// [`crate::envelope::review`].
///
/// # Safety
///
/// `ptr` and `len` name the input `alloc` made room for.
#[cfg(feature = "abi-review")]
#[no_mangle]
pub unsafe extern "C" fn review(ptr: *const u8, len: usize) -> u64 {
    out(crate::envelope::review(unsafe { input(ptr, len) }))
}

/// [`crate::envelope::witness`].
///
/// # Safety
///
/// `ptr` and `len` name the input `alloc` made room for.
#[cfg(feature = "abi-witness")]
#[no_mangle]
pub unsafe extern "C" fn witness(ptr: *const u8, len: usize) -> u64 {
    out(crate::envelope::witness(unsafe { input(ptr, len) }))
}

/// [`crate::envelope::chosen`].
///
/// # Safety
///
/// `ptr` and `len` name the input `alloc` made room for.
#[cfg(feature = "abi-review")]
#[no_mangle]
pub unsafe extern "C" fn chosen(ptr: *const u8, len: usize) -> u64 {
    out(crate::envelope::chosen(unsafe { input(ptr, len) }))
}

/// [`crate::envelope::budget`].
///
/// # Safety
///
/// `ptr` and `len` name the input `alloc` made room for.
#[cfg(feature = "abi-review")]
#[no_mangle]
pub unsafe extern "C" fn budget(ptr: *const u8, len: usize) -> u64 {
    out(crate::envelope::budget(unsafe { input(ptr, len) }))
}
