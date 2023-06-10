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
use std::ffi::{c_void, c_uchar, CStr, CString};
use std::os::raw::c_char;
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::slice::from_raw_parts;
use nix::errno::Errno::EAGAIN;
use nix::fcntl::{F_SETFL, OFlag};
use nix::libc::O_NONBLOCK;

use crate::abi::{CallFromHost, GuestFunction};
use crate::frameworks::core_foundation::cf_run_loop::{CFRunLoopGetMain, CFRunLoopRef};
use crate::frameworks::foundation::ns_run_loop::NSRunLoopHostObject;
use crate::libc::time::timeval;
use nix::sys::socket::{AddressFamily, MsgFlags, SockaddrIn, SockaddrLike, SockFlag, SockProtocol, SockType};

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
unsafe impl SafeRead for sockaddr_in {}

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
        // TODO: either DOOM is leaking here or ifa_addr should be copied by value and not stored in the heap
        //env.mem.free(curr.ifa_addr.cast());
        env.mem.free(curr_ptr.cast());

        curr_ptr = next_ptr;
    }
}

fn if_nameindex(_env: &mut Environment, _ifname: ConstPtr<u8>) -> i32 {
    0
}

fn if_indextoname(env: &mut Environment, ifindex: u32, ifname: ConstPtr<u8>) -> ConstPtr<u8> {
    assert_eq!(ifindex, 2);
    env.mem
        .bytes_at_mut(ifname.cast_mut(), 3)
        .copy_from_slice("en0".as_bytes());
    env.mem.write(ifname.cast_mut() + 3, b'\0');
    ifname
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
    regtype: ConstPtr<u8>,
    domain: ConstPtr<u8>,
    callBack: GuestFunction, // void (*DNSServiceBrowseReply)(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *serviceName, const char *regtype, const char *replyDomain, void *context)
    context: MutVoidPtr,
) -> i32 {
    assert_eq!(domain, Ptr::null());
    assert_eq!(context, Ptr::null());

    let mut service_ref: bonjour_sys::DNSServiceRef = null_mut();
    let service_type = CString::new(env.mem.cstr_at(regtype)).unwrap();
    let ptr = service_type.as_ptr();

    assert_eq!(env.current_thread, 0);
    let run_loop = CFRunLoopGetMain(env);
    let cq = env
        .objc
        .borrow::<NSRunLoopHostObject>(run_loop)
        .callbacks_queue
        .clone();

    let x = GuestFunctionWithCallbackQueue { cq, gf: callBack };
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
    log_dbg!("browse_callback, context {:p}", context);

    if error_code != bonjour_sys::kDNSServiceErr_NoError {
        log!("DNSServiceBrowser callback error: {}", error_code);
        return;
    }

    //let sd_ref_box = Box::new(sd_ref);

    let cstr_service_name = unsafe { CStr::from_ptr(service_name) }.to_owned();
    let cstr_regtype = unsafe { CStr::from_ptr(regtype) }.to_owned();
    let cstr_reply_domain = unsafe { CStr::from_ptr(reply_domain) }.to_owned();

    let boxx: Box<GuestFunctionWithCallbackQueue> = unsafe { Box::from_raw(context as *mut _) };
    let cq = boxx.cq.clone();
    let guest_callback = boxx.gf;

    let mut cq_mut = (*cq).borrow_mut();
    log!("browse_callback borrowing mut cq");
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

        let guest_regtype = env
            .mem
            .alloc_and_write_cstr(cstr_regtype.to_bytes())
            .cast_const();

        let guest_reply_domain = env
            .mem
            .alloc_and_write_cstr(cstr_reply_domain.to_bytes())
            .cast_const();

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
    }));

    assert_eq!(Box::into_raw(boxx) as *mut c_void, context);
}

fn DNSServiceResolve(
    env: &mut Environment,
    sdRef: MutPtr<DNSServiceRef>,
    flags: u32,
    interfaceIndex: u32,
    name: ConstPtr<u8>,
    regtype: ConstPtr<u8>,
    domain: ConstPtr<u8>,
    callBack: GuestFunction, // void (*DNSServiceResolveReply)(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *fullname, const char *hosttarget, uint16_t port, uint16_t txtLen, const unsigned char *txtRecord, void *context)
    context: MutVoidPtr,
) -> i32 {
    assert_eq!(flags, bonjour_sys::kDNSServiceFlagsForceMulticast);
    assert_eq!(interfaceIndex, 2); // en0

    let mut service_ref: bonjour_sys::DNSServiceRef = null_mut();

    let name_str = CString::new(env.mem.cstr_at(name)).unwrap();
    let name_str_ptr = name_str.as_ptr();

    let regtype_str = CString::new(env.mem.cstr_at(regtype)).unwrap();
    let regtype_str_ptr = regtype_str.as_ptr();

    let domain_str = CString::new(env.mem.cstr_at(domain)).unwrap();
    let domain_str_ptr = domain_str.as_ptr();

    assert_eq!(env.current_thread, 0);
    let run_loop = CFRunLoopGetMain(env);
    let cq = env
        .objc
        .borrow::<NSRunLoopHostObject>(run_loop)
        .callbacks_queue
        .clone();

    let x = GuestFunctionWithCallbackQueue { cq, gf: callBack };
    let boxed_callback = Box::new(x);

    let r = unsafe {
        bonjour_sys::DNSServiceResolve(
            &mut service_ref as _,
            flags,
            0,
            name_str_ptr,
            regtype_str_ptr,
            domain_str_ptr,
            Some(resolve_callback),
            Box::into_raw(boxed_callback) as *mut c_void,
        )
    };
    if r != bonjour_sys::kDNSServiceErr_NoError {
        log!("DNSServiceResolve error: {}", r);
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

unsafe extern "C" fn resolve_callback(
    sd_ref: bonjour_sys::DNSServiceRef,
    flags: bonjour_sys::DNSServiceFlags,
    interface_index: u32,
    error_code: bonjour_sys::DNSServiceErrorType,
    fullname: *const c_char,
    host_target: *const c_char,
    port: u16,
    txt_len: u16,
    txt_record: *const c_uchar,
    context: *mut c_void,
) {
    //assert_eq!(interface_index, 0);
    log!("resolve_callback, context {:p}", context);

    if error_code != bonjour_sys::kDNSServiceErr_NoError {
        log!("DNSServiceResolve callback error: {}", error_code);
        return;
    }

    let cstr_fullname = unsafe { CStr::from_ptr(fullname) }.to_owned();
    let cstr_host_target = unsafe { CStr::from_ptr(host_target) }.to_owned();
    let cstr_txt_record = unsafe { CStr::from_ptr(txt_record.cast()) }.to_owned();

    let boxx: Box<GuestFunctionWithCallbackQueue> = unsafe { Box::from_raw(context as *mut _) };
    let cq = boxx.cq.clone();
    let guest_callback = boxx.gf;

    let mut cq_mut = (*cq).borrow_mut();
    log!("resolve_callback borrowing mut cq");
    cq_mut.push(Box::new(move |env: &mut Environment| {
        let guest_sd_ref = env
            .libc_state
            .network
            .service_refs
            .iter()
            .find(|&(k, v)| v == &sd_ref)
            .unwrap()
            .0;

        let guest_fullname = env
            .mem
            .alloc_and_write_cstr(cstr_fullname.to_bytes())
            .cast_const();

        let guest_host_target = env
            .mem
            .alloc_and_write_cstr(cstr_host_target.to_bytes())
            .cast_const();

        let guest_txt_record = env
            .mem
            .alloc_and_write_cstr(cstr_txt_record.to_bytes())
            .cast_const();

        <GuestFunction as CallFromHost<
            (),
            (
                DNSServiceRef,
                u32,
                u32,
                i32,
                ConstPtr<u8>,
                ConstPtr<u8>,
                u16,
                u16,
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
                guest_fullname,
                guest_host_target,
                port,
                txt_len,
                guest_txt_record,
                Ptr::null(),
            ),
        );

        env.mem.free(guest_fullname.cast_mut().cast());
        env.mem.free(guest_host_target.cast_mut().cast());
        env.mem.free(guest_txt_record.cast_mut().cast());
    }));

    assert_eq!(Box::into_raw(boxx) as *mut c_void, context);
}

fn DNSServiceRegister(
    env: &mut Environment,
    sdRef: MutPtr<DNSServiceRef>,
    flags: u32,
    interfaceIndex: u32,
    name: ConstPtr<u8>,
    regtype: ConstPtr<u8>,
    domain: ConstPtr<u8>,
    host: ConstPtr<u8>,
    port: u16,
    txtLen: u16,
    txtRecord: ConstPtr<u8>,
    callBack: GuestFunction, // void (*DNSServiceRegisterReply)(DNSServiceRef sdRef, DNSServiceFlags flags, DNSServiceErrorType errorCode, const char *name, const char *regtype, const char *domain, void *context)
    context: MutVoidPtr,
) -> i32 {
    assert_eq!(flags, bonjour_sys::kDNSServiceFlagsNoAutoRename);
    //assert_eq!(interfaceIndex, 2); // en0

    assert_eq!(domain, ConstPtr::null());
    assert_eq!(host, ConstPtr::null());
    assert_eq!(txtLen, 0);
    assert_eq!(txtRecord, ConstPtr::null());
    assert_eq!(context, MutVoidPtr::null());

    let mut service_ref: bonjour_sys::DNSServiceRef = null_mut();

    let name_str = CString::new(env.mem.cstr_at(name)).unwrap();
    let name_str_ptr = name_str.as_ptr();

    let regtype_str = CString::new(env.mem.cstr_at(regtype)).unwrap();
    let regtype_str_ptr = regtype_str.as_ptr();

    assert_eq!(env.current_thread, 0);
    let run_loop = CFRunLoopGetMain(env);
    let cq = env
        .objc
        .borrow::<NSRunLoopHostObject>(run_loop)
        .callbacks_queue
        .clone();

    let x = GuestFunctionWithCallbackQueue { cq, gf: callBack };
    let boxed_callback = Box::new(x);

    let r = unsafe {
        bonjour_sys::DNSServiceRegister(
            &mut service_ref as _,
            flags,
            0,
            name_str_ptr,
            regtype_str_ptr,
            null(),
            null(),
            port,
            0,
            null(),
            Some(register_callback),
            Box::into_raw(boxed_callback) as *mut c_void,
        )
    };
    if r != bonjour_sys::kDNSServiceErr_NoError {
        log!("DNSServiceRegister error: {}", r);
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

unsafe extern "C" fn register_callback(
    sd_ref: bonjour_sys::DNSServiceRef,
    flags: bonjour_sys::DNSServiceFlags,
    error_code: bonjour_sys::DNSServiceErrorType,
    name: *const c_char,
    regtype: *const c_char,
    domain: *const c_char,
    context: *mut c_void,
) {
    log!("register_callback, context {:p}", context);

    let boxx: Box<GuestFunctionWithCallbackQueue> = unsafe { Box::from_raw(context as *mut _) };
    let cq = boxx.cq.clone();
    let guest_callback = boxx.gf;

    let mut cq_mut = (*cq).borrow_mut();
    log!("register_callback borrowing mut cq");
    cq_mut.push(Box::new(move |env: &mut Environment| {
        <GuestFunction as CallFromHost<
            (),
            (
                DNSServiceRef,
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
                Ptr::null(),
                0,
                error_code,
                ConstPtr::null(),
                ConstPtr::null(),
                ConstPtr::null(),
                Ptr::null(),
            ),
        );
    }));
 
    assert_eq!(Box::into_raw(boxx) as *mut c_void, context);
}

fn DNSServiceQueryRecord(
    env: &mut Environment,
    sdRef: MutPtr<DNSServiceRef>,
    flags: u32,
    interfaceIndex: u32,
    fullname: ConstPtr<u8>,
    rrtype: u16,
    rrclass: u16,
    callBack: GuestFunction, // void (*DNSServiceQueryRecordReply)(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *fullname, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata, uint32_t ttl, void *context)
    context: MutVoidPtr,
) -> i32 {
    assert_eq!(flags, bonjour_sys::kDNSServiceFlagsForceMulticast);
    assert_eq!(interfaceIndex, 2); // en0

    assert_eq!(rrtype, bonjour_sys::kDNSServiceType_A as u16);
    assert_eq!(rrclass, bonjour_sys::kDNSServiceClass_IN as u16);
    assert_eq!(context, MutVoidPtr::null());

    let mut service_ref: bonjour_sys::DNSServiceRef = null_mut();

    let fullname_str = CString::new(env.mem.cstr_at(fullname)).unwrap();
    let fullname_str_ptr = fullname_str.as_ptr();

    assert_eq!(env.current_thread, 0);
    let run_loop = CFRunLoopGetMain(env);
    let cq = env
        .objc
        .borrow::<NSRunLoopHostObject>(run_loop)
        .callbacks_queue
        .clone();

    let x = GuestFunctionWithCallbackQueue { cq, gf: callBack };
    let boxed_callback = Box::new(x);

    let r = unsafe {
        bonjour_sys::DNSServiceQueryRecord(
            &mut service_ref as _,
            flags,
            0,
            fullname_str_ptr,
            rrtype,
            rrclass,
            Some(query_record_callback),
            Box::into_raw(boxed_callback) as *mut c_void,
        )
    };
    if r != bonjour_sys::kDNSServiceErr_NoError {
        log!("DNSServiceQueryRecord error: {}", r);
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

unsafe extern "C" fn query_record_callback(
    sd_ref: bonjour_sys::DNSServiceRef,
    flags: bonjour_sys::DNSServiceFlags,
    interface_index: u32,
    error_code: bonjour_sys::DNSServiceErrorType,
    fullname: *const c_char,
    rrtype: u16,
    rrclass: u16,
    rdlen: u16,
    rdata: *const c_void,
    ttl: u32,
    context: *mut c_void,
) {
    log!("query_record_callback, context {:p}", context);

    assert_eq!(rdlen, 4);

    if error_code != bonjour_sys::kDNSServiceErr_NoError {
        log!("DNSServiceQueryRecord callback error: {}", error_code);
        return;
    }

    //let rdata_box = Box::new(rdata);
    let slice_tmp: &[u8] = unsafe { from_raw_parts(rdata.cast(), rdlen.into()) };
    let slice = slice_tmp.to_vec().into_boxed_slice();
    log!("slice before {:?}", &slice);
    //let y = Box::new(slice);

    let boxx: Box<GuestFunctionWithCallbackQueue> = unsafe { Box::from_raw(context as *mut _) };
    let cq = boxx.cq.clone();
    let guest_callback = boxx.gf;

    let mut cq_mut = (*cq).borrow_mut();
    log!("query_record_callback borrowing mut cq");
    cq_mut.push(Box::new(move |env: &mut Environment| {

        //let guest_rdata = env.mem.alloc_and_write(*rdata_box);
        let ptr = env.mem.alloc(rdlen.into()).cast();
        log!("slice after {:?}", &slice);
        env.mem.bytes_at_mut(ptr, rdlen.into()).copy_from_slice(&slice);

        <GuestFunction as CallFromHost<
            (),
            (
                DNSServiceRef,
                u32,
                u32,
                i32,
                ConstPtr<u8>,
                u16,
                u16,
                u16,
                ConstVoidPtr,
                u32,
                MutVoidPtr,
            ),
        >>::call_from_host(
            &guest_callback,
            env,
            (
                Ptr::null(),
                0,
                2, //interface_index,
                error_code,
                ConstPtr::null(),
                rrtype,
                rrclass,
                rdlen,
                ptr.cast_const().cast(),
                ttl,
                Ptr::null(),
            ),
        );
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

fn DNSServiceRefDeallocate(env: &mut Environment, sdRef: DNSServiceRef) {
    // let service_ref = State::get(env).service_refs.remove(&sdRef).unwrap();
    // env.mem.free(sdRef.cast());
    // unsafe { bonjour_sys::DNSServiceRefDeallocate(service_ref) };
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

fn socket(env: &mut Environment, domain: i32, type_: i32, protocol: i32) -> i32 {
    let res = nix::sys::socket::socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), SockProtocol::Udp);
    match res  {
        Ok(sock) => sock,
        Err(e) => {
            log!("host socket err {:?}", e);
            -1
        }
    }
}

fn bind(env: &mut Environment, socket: i32, address: ConstPtr<sockaddr_in>, _address_len: u32) -> i32 {
    let sockaddr = env.mem.read(address);
    let addr = sockaddr.sin_addr.s_addr.to_ne_bytes();
    // TODO: WTF, how does it even converts to 14666 ?
    log!("bind addr {} {} {} {} {}", addr[0], addr[1], addr[2], addr[3], sockaddr.sin_port.to_be());
    let host_sockaddr_in = SockaddrIn::new(addr[0], addr[1], addr[2], addr[3], sockaddr.sin_port.to_be());
    let res = nix::sys::socket::bind(socket, &host_sockaddr_in);
    if let Err(e) = res {
        log!("host bind err {:?}", e);
        return -1;
    }
    0
}

fn recvfrom(env: &mut Environment, socket: i32, buffer: MutVoidPtr, length: u32, flags: i32, address: MutPtr<sockaddr_in>, address_len: MutPtr<u32>) -> i32 {
    assert_eq!(flags, 0);

    // TODO: generalize errno
    env.libc_state.errno.set_errno_for_thread(&mut env.mem, env.current_thread, 0);

    let mut buf = [0u8; 1500usize];
    let res = nix::sys::socket::recvfrom(socket, &mut buf[..]);
    if let Err(e) = res {
        if e != EAGAIN {
            log!("host recvfrom err {:?}", e);
        }
        env.libc_state.errno.set_errno_for_thread(&mut env.mem, env.current_thread, e as i32);
        return -1;
    }
    let (received, maybe_inet): (usize, Option<SockaddrIn>) = res.unwrap();
    env.mem
        .bytes_at_mut(buffer.cast(), received as u32)
        .copy_from_slice(&buf[..received]);
    let inet = maybe_inet.unwrap();
    let addr_in = sockaddr_in {
        sin_len: 0,
        sin_family: nix::sys::socket::AddressFamily::Inet as u8,
        sin_port: inet.port(),
        sin_addr: in_addr {
            s_addr: inet.ip().to_be(),
        },
        sin_zero: [0; 8],
    };
    env.mem.write(address, addr_in);
    received as i32
}

#[allow(unaligned_references)]
fn sendto(env: &mut Environment, socket: i32, buffer: ConstVoidPtr, length: u32, flags: i32, address: ConstPtr<sockaddr_in>, address_len: MutPtr<u32>) -> i32 {
    assert_eq!(flags, 0);

    let sockaddr = env.mem.read(address);
    let addr = sockaddr.sin_addr.s_addr.to_ne_bytes();
    // TODO: WTF, how does it even converts to 14666 ?
    //log!("sendto addr {} {} {} {} {}", addr[0], addr[1], addr[2], addr[3], sockaddr.sin_port);
    let host_sockaddr_in = SockaddrIn::new(addr[0], addr[1], addr[2], addr[3], sockaddr.sin_port);

    // TODO: is it OK to read directly from guest memory?
    let buf = env.mem.bytes_at(buffer.cast(), length);
    let res = nix::sys::socket::sendto(socket, &buf,  &host_sockaddr_in, MsgFlags::empty());
    match res {
        Ok(sent) => sent as i32,
        Err(e) => {
            log!("host sendto err {:?}", e);
            return -1;
        }
    }
}

fn fcntl(env: &mut Environment, fd: i32, cmd: i32, flag: i32) -> i32 {
    nix::fcntl::fcntl(fd, F_SETFL(OFlag::O_NONBLOCK)).unwrap()
}

pub const FUNCTIONS: FunctionExports = &[
    export_c_func!(getifaddrs(_)),
    export_c_func!(freeifaddrs(_)),
    export_c_func!(if_nameindex(_)),
    export_c_func!(if_indextoname(_, _)),
    export_c_func!(DNSServiceBrowse(_, _, _, _, _, _, _)),
    export_c_func!(DNSServiceResolve(_, _, _, _, _, _, _, _)),
    export_c_func!(DNSServiceRegister(_, _, _, _, _, _, _, _, _, _, _, _)),
    export_c_func!(DNSServiceQueryRecord(_, _, _, _, _, _, _, _)),
    export_c_func!(DNSServiceRefSockFD(_)),
    export_c_func!(DNSServiceProcessResult(_)),
    export_c_func!(DNSServiceRefDeallocate(_)),
    export_c_func!(select(_, _, _, _, _)),
    export_c_func!(socket(_, _, _)),
    export_c_func!(bind(_, _, _)),
    export_c_func!(fcntl(_, _, _)),
    export_c_func!(recvfrom(_, _, _, _, _, _)),
    export_c_func!(sendto(_, _, _, _, _, _)),
];
