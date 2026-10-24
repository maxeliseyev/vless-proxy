//! The C ABI as the Swift side uses it: start, push a DNS query packet,
//! get the answer through the packet callback, stop.

use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use std::ffi::{c_void, CStr, CString};
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::time::Duration;
use vproxy::netstack::fakedns::{FakeDns, DEFAULT_POOL};
use vproxy_ffi::*;

extern "C" fn collect(ctx: *mut c_void, packet: *const u8, len: usize) {
    let sender = unsafe { &*(ctx as *const mpsc::Sender<Vec<u8>>) };
    let bytes = unsafe { std::slice::from_raw_parts(packet, len) }.to_vec();
    let _ = sender.send(bytes);
}

/// Nothing listens there: the server is only dialled for real traffic.
const LINK: &str =
    "vless://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@127.0.0.1:9?security=none&type=tcp";

#[test]
fn dns_query_round_trips_through_the_c_abi() {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let ctx = Box::into_raw(Box::new(tx));
    let link = CString::new(LINK).unwrap();
    let mut error = [0 as std::ffi::c_char; 256];
    let tunnel = unsafe {
        ratatosk_start(
            link.as_ptr(),
            1500,
            collect,
            ctx.cast(),
            error.as_mut_ptr(),
            error.len(),
        )
    };
    assert!(!tunnel.is_null(), "{:?}", unsafe {
        CStr::from_ptr(error.as_ptr())
    });

    let mut query = vec![0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["ifconfig", "me"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let builder = PacketBuilder::ipv4([10, 0, 0, 2], [198, 18, 0, 2], 64).udp(53_000, 53);
    let mut packet = Vec::new();
    builder.write(&mut packet, &query).unwrap();
    assert!(unsafe { ratatosk_push_packet(tunnel, packet.as_ptr(), packet.len()) });

    let reply = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("no packet back");
    let sliced = SlicedPacket::from_ip(&reply).unwrap();
    let (Some(NetSlice::Ipv4(ip)), Some(TransportSlice::Udp(udp))) =
        (&sliced.net, &sliced.transport)
    else {
        panic!("not an IPv4 UDP packet");
    };
    assert_eq!(ip.header().destination_addr(), Ipv4Addr::new(10, 0, 0, 2));
    assert_eq!(udp.destination_port(), 53_000);
    let answer = udp.payload();
    assert_eq!(&answer[..2], &[0x42, 0x42]);
    assert_eq!(&answer[answer.len() - 4..answer.len() - 2], &[198, 18]);

    let mut stats = RatatoskStats::default();
    unsafe { ratatosk_stats(&mut stats) };
    unsafe { ratatosk_stop(tunnel) };
    drop(unsafe { Box::from_raw(ctx) });
}

#[test]
fn bad_link_is_refused_with_a_reason() {
    let link = CString::new("vless://not-a-uuid@host:443").unwrap();
    let mut error = [0 as std::ffi::c_char; 256];
    extern "C" fn ignore(_: *mut c_void, _: *const u8, _: usize) {}
    let tunnel = unsafe {
        ratatosk_start(
            link.as_ptr(),
            1500,
            ignore,
            std::ptr::null_mut(),
            error.as_mut_ptr(),
            error.len(),
        )
    };
    assert!(tunnel.is_null());
    let reason = unsafe { CStr::from_ptr(error.as_ptr()) }.to_str().unwrap();
    assert!(reason.contains("UUID"), "{reason}");
}

#[test]
fn header_addresses_match_the_core() {
    let header = include_str!("../include/ratatosk.h");
    let define = |name: &str| -> Ipv4Addr {
        let line = header
            .lines()
            .find(|l| l.starts_with(&format!("#define {name} ")))
            .unwrap_or_else(|| panic!("{name} missing"));
        line.split('"').nth(1).unwrap().parse().unwrap()
    };
    let dns = FakeDns::new(DEFAULT_POOL, 1024);
    assert_eq!(define("RATATOSK_DNS_ADDRESS"), dns.server_addr());
    let tunnel = define("RATATOSK_TUNNEL_ADDRESS");
    assert!(dns.is_fake(tunnel) && dns.domain_for(tunnel).is_none());
    assert_eq!(
        define("RATATOSK_TUNNEL_NETMASK"),
        Ipv4Addr::new(255, 254, 0, 0)
    );
}
