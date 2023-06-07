/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use crate::dyld::FunctionExports;
use crate::environment::Environment;
use crate::export_c_func;
use crate::mem::{
    guest_size_of, ConstPtr, ConstVoidPtr, MutPtr, MutVoidPtr, Ptr, SafeRead, SafeWrite,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_void, CStr, CString};
use std::os::raw::c_char;
use std::ptr::{null, null_mut};
use std::rc::Rc;

use crate::abi::{CallFromHost, GuestFunction};
use crate::frameworks::core_foundation::cf_run_loop::{CFRunLoopGetMain, CFRunLoopRef};
use crate::frameworks::foundation::ns_run_loop::NSRunLoopHostObject;
use crate::libc::time::timeval;
use nix::sys::socket::SockaddrLike;

#[derive(Default)]
pub struct State {
    service_refs: HashMap<DNSServiceRef, bonjour_sys::DNSServiceRef>,
}
impl State {
    fn get(env: &mut Environment) -> &mut Self {
        &mut env.libc_state.network
    }
}

#[allow(non_camel_case_types)]
type dnssd_sock_t = i32;

#[repr(C, packed)]
#[allow(non_camel_case_types)]
struct _DNSServiceRef_t {
    _unused: u8,
}
impl SafeWrite for _DNSServiceRef_t {}
type DNSServiceRef = MutPtr<_DNSServiceRef_t>;

#[repr(C, packed)]
#[allow(non_camel_case_types)]
struct sockaddr_in {
    sin_len: u8,
    sin_family: u8,    // e.g. AF_INET
    sin_port: u16,     // e.g. htons(3490)
    sin_addr: in_addr, // see struct in_addr, below
    sin_zero: [u8; 8], // zero this if you want to
}
impl SafeWrite for sockaddr_in {}

#[repr(C, packed)]
#[allow(non_camel_case_types)]
struct in_addr {
    s_addr: u32, // load with inet_aton()
}
impl SafeWrite for in_addr {}

#[repr(C, packed)]
#[allow(non_camel_case_types)]
struct ifaddrs {
    ifa_next: MutPtr<ifaddrs>,        /* Pointer to next struct */
    ifa_name: MutPtr<u8>,             /* Interface name */
    ifa_flags: u32,                   /* Interface flags */
    ifa_addr: MutPtr<sockaddr_in>,    /* Interface address */
    ifa_netmask: MutPtr<sockaddr_in>, /* Interface netmask */
    ifa_dstaddr: MutPtr<sockaddr_in>, /* P2P interface destination */
    ifa_data: MutVoidPtr,             /* Address specific data */
}
unsafe impl SafeRead for ifaddrs {}

fn getifaddrs(env: &mut Environment, ifap: MutPtr<MutPtr<ifaddrs>>) -> i32 {
    let mut prev: MutPtr<ifaddrs> = Ptr::null();

    let addrs = nix::ifaddrs::getifaddrs().unwrap();
    for iface in addrs {
        if iface.interface_name != "en0" {
            // TODO: more interfaces?
            continue;
        }
        let sock = if let Some(sock) = iface.address {
            sock
        } else {
            continue;
        };
        if sock.family() == Some(nix::sys::socket::AddressFamily::Inet) {
            let inet = sock.as_sockaddr_in().unwrap();
            // println!("name {}", iface.interface_name);
            // println!("address {}", iface.address.unwrap());
            // println!("inet {}", inet);
            // println!("inet ip {}", inet.ip());

            let addr_in = sockaddr_in {
                sin_len: 0,
                sin_family: nix::sys::socket::AddressFamily::Inet as u8,
                sin_port: inet.port(),
                sin_addr: in_addr {
                    s_addr: inet.ip().to_be(),
                },
                sin_zero: [0; 8],
            };

            let addr_in_ptr = env.mem.alloc_and_write(addr_in);

            let ifadd = ifaddrs {
                ifa_next: prev,
                ifa_name: env
                    .mem
                    .alloc_and_write_cstr(iface.interface_name.as_bytes()),
                ifa_flags: 0,
                ifa_addr: addr_in_ptr,
                ifa_netmask: Ptr::null(),
                ifa_dstaddr: Ptr::null(),
                ifa_data: Ptr::null(),
            };

            let ifadd_ptr = env.mem.alloc_and_write(ifadd);
            prev = ifadd_ptr;
        }
    }
    env.mem.write(ifap, prev);
    0
}

fn freeifaddrs(env: &mut Environment, ifp: MutPtr<ifaddrs>) {
    let mut next_ptr: MutPtr<ifaddrs> = Ptr::null();
    let mut curr_ptr = ifp;
    while !curr_ptr.is_null() {
        let curr = env.mem.read(curr_ptr);
        next_ptr = curr.ifa_next;

        env.mem.free(curr.ifa_name.cast());
        env.mem.free(curr.ifa_addr.cast());
        env.mem.free(curr_ptr.cast());

        curr_ptr = next_ptr;
    }
}

fn if_nameindex(_env: &mut Environment, _ifname: ConstPtr<u8>) -> i32 {
    0
}

struct GuestFunctionWithCallbackQueue {
    cq: Rc<RefCell<Vec<Box<dyn FnOnce(&mut Environment)>>>>,
    gf: GuestFunction,
}

fn DNSServiceBrowse(
    env: &mut Environment,
    sdRef: MutPtr<DNSServiceRef>,
    _flags: u32,
    _interfaceIndex: u32,
    _regtype: ConstPtr<u8>,
    _domain: ConstPtr<u8>,
    callBack: GuestFunction, // void (*DNSServiceBrowseReply)(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *serviceName, const char *regtype, const char *replyDomain, void *context)
    _context: MutVoidPtr,
) -> i32 {
    //"_DoomServer._udp."
    let mut service_ref: bonjour_sys::DNSServiceRef = null_mut();
    let service_type = CString::new("_DoomServer._udp.").unwrap();
    let ptr = service_type.as_ptr();

    assert_eq!(env.current_thread, 0);
    let run_loop = CFRunLoopGetMain(env);
    let cq = env
        .objc
        .borrow::<NSRunLoopHostObject>(run_loop)
        .callbacks_queue
        .clone();

    let x = GuestFunctionWithCallbackQueue { cq, gf: callBack };
    log!("before callback {:?}", callBack);
    let boxed_callback = Box::new(x);
    let r = unsafe {
        bonjour_sys::DNSServiceBrowse(
            &mut service_ref as _,
            0,
            0,
            ptr,
            null(),
            Some(browse_callback),
            Box::into_raw(boxed_callback) as *mut c_void,
        )
    };
    if r != bonjour_sys::kDNSServiceErr_NoError {
        log!("DNSServiceBrowser error: {}", r);
        return -1;
    }
    let guest_service_ref = env.mem.alloc_and_write(_DNSServiceRef_t { _unused: 0 });
    env.mem.write(sdRef, guest_service_ref);

    assert!(!State::get(env)
        .service_refs
        .contains_key(&guest_service_ref));
    State::get(env)
        .service_refs
        .insert(guest_service_ref, service_ref);

    0 // NoError
}

unsafe extern "C" fn browse_callback(
    sd_ref: bonjour_sys::DNSServiceRef,
    flags: bonjour_sys::DNSServiceFlags,
    _interface_index: u32,
    error_code: bonjour_sys::DNSServiceErrorType,
    service_name: *const c_char,
    regtype: *const c_char,
    reply_domain: *const c_char,
    context: *mut c_void,
) {
    log!("browse_callback, context {:p}", context);

    if error_code != bonjour_sys::kDNSServiceErr_NoError {
        log!("DNSServiceBrowser callback error: {}", error_code);
        return;
    }

    let cstr_service_name = unsafe { CStr::from_ptr(service_name) }.to_owned();
    let cstr_regtype = unsafe { CStr::from_ptr(regtype) }.to_owned();
    let cstr_reply_domain = unsafe { CStr::from_ptr(reply_domain) }.to_owned();

    log!(
        "cstrs {:?} {:?} {:?}",
        cstr_service_name,
        cstr_regtype,
        cstr_reply_domain
    );

    let boxx: Box<GuestFunctionWithCallbackQueue> = unsafe { Box::from_raw(context as *mut _) };
    let cq = boxx.cq.clone();
    let guest_callback = boxx.gf;

    let mut cq_mut = (*cq).borrow_mut();
    cq_mut.push(Box::new(move |env: &mut Environment| {
        log!("after callback {:?}", guest_callback);
        let guest_sd_ref = env
            .libc_state
            .network
            .service_refs
            .iter()
            .find(|&(k, v)| v == &sd_ref)
            .unwrap()
            .0;

        let guest_service_name = env
            .mem
            .alloc_and_write_cstr(cstr_service_name.to_bytes())
            .cast_const();

        log!(
            "guest_service_name {:?} {:?}",
            guest_service_name,
            env.mem.cstr_at_utf8(guest_service_name)
        );

        let guest_regtype = env
            .mem
            .alloc_and_write_cstr(cstr_regtype.to_bytes())
            .cast_const();

        log!(
            "guest_regtype {:?} {:?}",
            guest_regtype,
            env.mem.cstr_at_utf8(guest_regtype)
        );

        let guest_reply_domain = env
            .mem
            .alloc_and_write_cstr(cstr_reply_domain.to_bytes())
            .cast_const();

        log!(
            "guest_reply_domain {:?} {:?}",
            guest_reply_domain,
            env.mem.cstr_at_utf8(guest_reply_domain)
        );

        <GuestFunction as CallFromHost<
            (),
            (
                DNSServiceRef,
                u32,
                u32,
                i32,
                ConstPtr<u8>,
                ConstPtr<u8>,
                ConstPtr<u8>,
                MutVoidPtr,
            ),
        >>::call_from_host(
            &guest_callback,
            env,
            (
                *guest_sd_ref,
                flags,
                2, //interface_index,
                error_code,
                guest_service_name,
                guest_regtype,
                guest_reply_domain,
                Ptr::null(),
            ),
        );

        env.mem.free(guest_reply_domain.cast_mut().cast());
        env.mem.free(guest_regtype.cast_mut().cast());
        env.mem.free(guest_service_name.cast_mut().cast());
        //callback.call_from_host(env, (context_ptr, …));
    }));

    assert_eq!(Box::into_raw(boxx) as *mut c_void, context);
}

fn DNSServiceRefSockFD(env: &mut Environment, sdRef: DNSServiceRef) -> i32 {
    let service_ref: &_ = State::get(env).service_refs.get(&sdRef).unwrap();
    // TODO: do not leak host socket to guest
    let sock = unsafe { bonjour_sys::DNSServiceRefSockFD(*service_ref) };
    log_dbg!("DNSServiceRefSockFD sock: {}", sock);
    sock
}

fn DNSServiceProcessResult(env: &mut Environment, sdRef: DNSServiceRef) -> i32 {
    let service_ref: &_ = State::get(env).service_refs.get(&sdRef).unwrap();
    let r = unsafe { bonjour_sys::DNSServiceProcessResult(*service_ref) };
    if r != bonjour_sys::kDNSServiceErr_NoError {
        log!("DNSServiceProcessResult error: {}", r);
        return -1;
    }
    0 // NoError
}

fn select(
    env: &mut Environment,
    nfds: i32,
    readfds: MutVoidPtr,
    writefds: MutVoidPtr,
    errorfds: MutVoidPtr,
    timeout: MutPtr<timeval>,
) -> i32 {
    let timeout_val = env.mem.read(timeout);
    log_dbg!(
        "{} {:?} {:?} {:?} {:?}",
        nfds,
        readfds,
        writefds,
        errorfds,
        timeout_val
    );
    // we're abusing the fact that for DOOM select is called with socket+1 as first arg
    // TODO: parse and retrieve values of fd_sets
    let sock = nfds - 1;

    let mut fd_set = nix::sys::select::FdSet::new();
    fd_set.insert(sock);

    let mut host_timeout =
        nix::sys::time::TimeVal::new(timeout_val.tv_sec.into(), timeout_val.tv_usec.into());

    nix::sys::select::select(None, &mut fd_set, None, None, &mut host_timeout).unwrap()
}

pub const FUNCTIONS: FunctionExports = &[
    export_c_func!(getifaddrs(_)),
    export_c_func!(freeifaddrs(_)),
    export_c_func!(if_nameindex(_)),
    export_c_func!(DNSServiceBrowse(_, _, _, _, _, _, _)),
    export_c_func!(DNSServiceRefSockFD(_)),
    export_c_func!(DNSServiceProcessResult(_)),
    export_c_func!(select(_, _, _, _, _)),
];
