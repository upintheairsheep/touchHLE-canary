/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! `NSURLRequest`.

use crate::mem::Ptr;
use crate::frameworks::foundation::ns_url;
use crate::objc::{id, msg_class, objc_classes, ClassExports};

pub const CLASSES: ClassExports = objc_classes! {

(env, this, _cmd);

@implementation NSURLRequest: NSObject

+ (id)requestWithURL:(id)url { // NSURL*
    log!(
        "TODO: [(NSURLRequest*){:?} requestWithURL:{:?} ({:?})]",
        this,
        url,
        ns_url::to_rust_path(env, url),
    );

    Ptr::null()
}

@end

};