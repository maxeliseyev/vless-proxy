//! The C ABI as the Swift side uses it: start, push a DNS query packet,
//! get the answer through the packet callback, stop.

use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use std::ffi::{c_void, CStr, CString};
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::time::Duration;
use vproxy::netstack::fakedns::{FakeDns, DEFAULT_POOL};
use vproxy_ffi::*;

extern "C" fn collect(
    ctx: *mut c_void,
    packets: *const *const u8,
    lens: *const usize,
    count: usize,
) {
    let sender = unsafe { &*(ctx as *const mpsc::Sender<Vec<u8>>) };
    for i in 0..count {
        let bytes = unsafe { std::slice::from_raw_parts(*packets.add(i), *lens.add(i)) }.to_vec();
        let _ = sender.send(bytes);
    }
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
    extern "C" fn ignore(_: *mut c_void, _: *const *const u8, _: *const usize, _: usize) {}
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

/// Take a string the core returned and free it.
fn take(s: *mut std::ffi::c_char) -> String {
    assert!(!s.is_null());
    let out = unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_owned();
    unsafe { ratatosk_string_free(s) };
    out
}

#[test]
fn ping_reports_each_server_or_null() {
    // security=none: the handshake is just TCP, so a listener answers it.
    let open = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let link = |port: u16| {
        format!("vless://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@127.0.0.1:{port}?security=none")
    };
    let links = serde_json::json!([
        link(open.local_addr().unwrap().port()),
        "not a link",
        link(closed_port)
    ])
    .to_string();
    let links = CString::new(links).unwrap();
    let out = take(unsafe { ratatosk_ping(links.as_ptr(), 2000) });
    let ms: Vec<Option<u64>> = serde_json::from_str(&out).unwrap();
    assert_eq!(ms.len(), 3, "{out}");
    assert!(
        ms[0].is_some() && ms[1].is_none() && ms[2].is_none(),
        "{out}"
    );

    let garbage = CString::new("{").unwrap();
    assert!(unsafe { ratatosk_ping(garbage.as_ptr(), 100) }.is_null());
}

#[test]
fn subscription_comes_back_with_links_and_traffic() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0u8; 2048];
        let _ = socket.read(&mut request);
        let body = "vless://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@a.example:443?security=tls#a\n\
                    h3://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@b.example:8445?sni=b.example#b\n\
                    trojan://skipped@c.example:443\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\
             subscription-userinfo: upload=1000; download=41000; total=100000; expire=1900000000\r\n\
             profile-title: demo\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).unwrap();
    });
    let url = CString::new(format!("http://127.0.0.1:{port}/sub/token")).unwrap();
    let out = take(unsafe { ratatosk_fetch_subscription(url.as_ptr()) });
    let sub: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(sub["title"], "demo", "{out}");
    assert_eq!(sub["links"].as_array().unwrap().len(), 2, "{out}");
    assert_eq!(sub["skipped"], 1);
    assert_eq!(
        (sub["download"].as_u64(), sub["total"].as_u64()),
        (Some(41000), Some(100000))
    );

    let nowhere = CString::new("http://127.0.0.1:9/").unwrap();
    let out = take(unsafe { ratatosk_fetch_subscription(nowhere.as_ptr()) });
    assert!(out.contains("\"error\""), "{out}");
}
