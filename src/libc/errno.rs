/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! `errno.h`

use crate::dyld::FunctionExports;
use crate::environment::Environment;
use crate::export_c_func;
use crate::mem::MutPtr;

pub const EPERM: i32 = 1;
pub const EDEADLK: i32 = 11;
pub const EINVAL: i32 = 22;

fn __error(env: &mut Environment) -> MutPtr<i32> {
    // TODO: avoid writing on each call!
    // TODO: "real" errno implementation
    env.mem.alloc_and_write(0i32)
}

pub const FUNCTIONS: FunctionExports = &[export_c_func!(__error())];