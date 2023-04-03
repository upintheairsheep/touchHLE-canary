/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! `CGImage.h`

use std::ffi::c_int;
use super::cg_color_space::{kCGColorSpaceGenericRGB, CGColorSpaceCreateWithName, CGColorSpaceRef};
use crate::dyld::{export_c_func, FunctionExports};
use crate::frameworks::core_foundation::{CFIndex, CFRelease, CFRetain, CFTypeRef};
use crate::frameworks::foundation::ns_string;
use crate::image::Image;
use crate::mem::{GuestUSize, MutPtr, Ptr, SafeRead};
use crate::objc::{objc_classes, ClassExports, HostObject, ObjC};
use crate::{Environment, impl_GuestRet_for_large_struct};
use crate::abi::GuestArg;

pub type CGImageAlphaInfo = u32;
pub const kCGImageAlphaNone: CGImageAlphaInfo = 0;
pub const kCGImageAlphaPremultipliedLast: CGImageAlphaInfo = 1;
pub const kCGImageAlphaPremultipliedFirst: CGImageAlphaInfo = 2;
pub const kCGImageAlphaLast: CGImageAlphaInfo = 3;
pub const kCGImageAlphaFirst: CGImageAlphaInfo = 4;
pub const kCGImageAlphaNoneSkipLast: CGImageAlphaInfo = 5;
pub const kCGImageAlphaNoneSkipFirst: CGImageAlphaInfo = 6;
pub const kCGImageAlphaOnly: CGImageAlphaInfo = 7;

pub type CGImageByteOrderInfo = u32;
pub const kCGImageByteOrderMask: CGImageByteOrderInfo = 0x7000;
pub const kCGImageByteOrderDefault: CGImageByteOrderInfo = 0 << 12;
#[allow(dead_code)]
pub const kCGImageByteOrder16Little: CGImageByteOrderInfo = 1 << 12;
#[allow(dead_code)]
pub const kCGImageByteOrder32Little: CGImageByteOrderInfo = 2 << 12;
#[allow(dead_code)]
pub const kCGImageByteOrder16Big: CGImageByteOrderInfo = 3 << 12;
pub const kCGImageByteOrder32Big: CGImageByteOrderInfo = 4 << 12;

pub type CGBitmapInfo = u32;
pub const kCGBitmapAlphaInfoMask: CGBitmapInfo = 0x1F; // huh, it's not 0x7?
pub const kCGBitmapByteOrderMask: CGBitmapInfo = kCGImageByteOrderMask;
// TODO: other stuff in this enum (for now, always assert the rest is 0)

pub const CLASSES: ClassExports = objc_classes! {

(env, this, _cmd);

// CGImage seems to be a CFType-based type, but in our implementation those
// are just Objective-C types, so we need a class for it, but its name is not
// visible anywhere.
@implementation _touchHLE_CGImage: NSObject
@end

};

struct CGImageHostObject {
    image: Image,
}
impl HostObject for CGImageHostObject {}

// TODO: CGImageCreate family. Currently the accessor on UIImage is the only way
//       to create this type.

pub type CGImageRef = CFTypeRef;
pub fn CGImageRelease(env: &mut Environment, c: CGImageRef) {
    if !c.is_null() {
        CFRelease(env, c);
    }
}
pub fn CGImageRetain(env: &mut Environment, c: CGImageRef) -> CGImageRef {
    if !c.is_null() {
        CFRetain(env, c)
    } else {
        c
    }
}

/// Shortcut for use by `UIImage`: directly construct a `CGImage` instance from
/// an [Image] instance.
pub fn from_image(env: &mut Environment, image: Image) -> CGImageRef {
    let host_obj = Box::new(CGImageHostObject { image });
    let class = env.objc.get_known_class("_touchHLE_CGImage", &mut env.mem);
    env.objc.alloc_object(class, host_obj, &mut env.mem)
}

/// Shortcut for use by `CGBitmapContext` etc: borrow the [Image] from a
/// `CGImage` instance.
pub fn borrow_image(objc: &ObjC, image: CGImageRef) -> &Image {
    &objc.borrow::<CGImageHostObject>(image).image
}

fn CGImageGetAlphaInfo(_env: &mut Environment, _image: CGImageRef) -> CGImageAlphaInfo {
    // our Image type always returns un-premultiplied RGBA
    // TODO: check if this is faithful to e.g. the real UIImage; it probably
    // uses premultiplied BGRA, considering the design of the CgBI format
    kCGImageAlphaLast
}

fn CGImageGetColorSpace(env: &mut Environment, _image: CGImageRef) -> CGColorSpaceRef {
    // Caller must release
    // FIXME: what if a loaded image is not sRGB?

    let srgb_name = ns_string::get_static_str(env, kCGColorSpaceGenericRGB);
    CGColorSpaceCreateWithName(env, srgb_name)
}

fn CGImageGetWidth(env: &mut Environment, image: CGImageRef) -> GuestUSize {
    let (width, _height) = env
        .objc
        .borrow::<CGImageHostObject>(image)
        .image
        .dimensions();
    width
}
fn CGImageGetHeight(env: &mut Environment, image: CGImageRef) -> GuestUSize {
    let (_width, height) = env
        .objc
        .borrow::<CGImageHostObject>(image)
        .image
        .dimensions();
    height
}

pub type CGDataProviderRef = CFTypeRef;
fn CGImageGetDataProvider(env: &mut Environment, image: CGImageRef) -> CGDataProviderRef {
    // TODO: implement proper provider?
    image
}

// TODO: move to proper module
pub type CFDataRef = CFTypeRef;
fn CGDataProviderCopyData(env: &mut Environment, provider: CGDataProviderRef) -> CFDataRef {
    // TODO: copy...
    // copy raw pixels with host memcopy
    // create a new image backed with those pixels
    // convert to cgimageref and return
    provider
}

fn CFDataGetLength(env: &mut Environment, data: CFDataRef) -> CFIndex {
    borrow_image(&env.objc, data).len().try_into().unwrap()
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct CFRange {
    pub location: CFIndex,
    pub length: CFIndex,
}

unsafe impl SafeRead for CFRange {}
impl_GuestRet_for_large_struct!(CFRange);
impl GuestArg for CFRange {
    const REG_COUNT: usize = 2;

    fn from_regs(regs: &[u32]) -> Self {
        CFRange {
            location: GuestArg::from_regs(&regs[0..1]),
            length: GuestArg::from_regs(&regs[1..2]),
        }
    }
    fn to_regs(self, regs: &mut [u32]) {
        self.location.to_regs(&mut regs[0..1]);
        self.length.to_regs(&mut regs[1..2]);
    }
}

fn CFDataGetBytes(env: &mut Environment, data: CFDataRef, range: CFRange, buffer: MutPtr<u8>) {
    // TODO: assert that `data` is actually CGImageRef before copying
    // TODO: actually support CFDataRef :p
    let src_pixels = borrow_image(&env.objc, data).pixels();
    let len = src_pixels.len().try_into().unwrap();
    // TODO: respect range
    // for i in range.location..(range.location + range.length) {
    //
    // }
    let _ = &env.mem.bytes_at_mut(buffer, len).copy_from_slice(src_pixels);
}

pub const FUNCTIONS: FunctionExports = &[
    export_c_func!(CGImageRelease(_)),
    export_c_func!(CGImageRetain(_)),
    export_c_func!(CGImageGetAlphaInfo(_)),
    export_c_func!(CGImageGetColorSpace(_)),
    export_c_func!(CGImageGetWidth(_)),
    export_c_func!(CGImageGetHeight(_)),
    export_c_func!(CGImageGetDataProvider(_)),
    // TODO: move to cg_data.rs
    export_c_func!(CGDataProviderCopyData(_)),
    export_c_func!(CFDataGetLength(_)),
    export_c_func!(CFDataGetBytes(_, _, _)),
];
