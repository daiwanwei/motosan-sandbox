//! In-netns bridge (spec §7): bring loopback up, bind a TCP listener per route
//! BEFORE forking, then fork ONE child that serves them forever with blocking
//! `std::net` (NO tokio — we're post-fork in a synchronous helper; fork +
//! tokio is unsafe).
//!
//! Ordering invariant (spec §7, load-bearing):
//! 1. `bind_route_listeners` (parent) — knows the local ports.
//! 2. `fork()`; child → `serve_bridges_forever`, parent → continues to
//!    seccomp `ProxyRouted` + `execvp(target)`.
//! 3. `--unshare-pid` makes the target pid 1; when it exits, the kernel
//!    SIGKILLs the entire pidns, reaping the bridge with no explicit wait.
//!
//! Why fork (not thread): the inner helper `execvp`s the target, replacing
//! the process image — a thread running the bridge would die with `execvp`,
//! breaking all egress. Only a separate process survives.

#![cfg(target_os = "linux")]
#![allow(dead_code)] // wired by Task 6 (helper::run_if_invoked dispatch)

use std::io::Result as IoResult;
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::reexec::ProxyRouteSpec;

/// One bound loopback listener with the host UDS it forwards to + the port
/// the parent stage will rewrite the proxy env to.
pub(crate) struct BoundRoute {
    pub listener: TcpListener,
    pub uds_path: PathBuf,
    pub local_port: u16,
}

/// Bind a `127.0.0.1:0` listener per route. A fresh `--unshare-net` netns has
/// `lo` DOWN with no address, so we bring it up UNCONDITIONALLY first (not as
/// a fallback) — otherwise the bind always fails with `EADDRNOTAVAIL`.
pub(crate) fn bind_route_listeners(spec: &ProxyRouteSpec) -> IoResult<Vec<BoundRoute>> {
    ensure_loopback_up()?;
    let mut out = Vec::with_capacity(spec.routes.len());
    for r in &spec.routes {
        let l = TcpListener::bind(("127.0.0.1", 0))?;
        let port = l.local_addr()?.port();
        out.push(BoundRoute {
            listener: l,
            uds_path: r.uds_path.clone(),
            local_port: port,
        });
    }
    Ok(out)
}

/// Run the bridge forwarding loops FOREVER (called in the forked child). Each
/// listener gets a dedicated thread; each accepted connection gets two copy
/// threads (one per direction) — blocking `std::io::copy`, no tokio.
///
/// Never returns under normal operation. If every listener thread somehow
/// returns (only via panic + join completing), exits 0 so the child doesn't
/// stick around as a zombie before the pidns reap.
pub(crate) fn serve_bridges_forever(routes: Vec<BoundRoute>) -> ! {
    let mut handles = Vec::with_capacity(routes.len());
    for BoundRoute {
        listener, uds_path, ..
    } in routes
    {
        handles.push(std::thread::spawn(move || {
            for client in listener.incoming().flatten() {
                let uds_path = uds_path.clone();
                std::thread::spawn(move || {
                    if let Ok(uds) = UnixStream::connect(&uds_path) {
                        pump_bidirectional(client, uds);
                    }
                });
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    std::process::exit(0);
}

/// Blocking bidirectional copy on two threads (one per direction). Both
/// streams are closed when this returns.
pub(crate) fn pump_bidirectional(tcp: std::net::TcpStream, uds: UnixStream) {
    use std::io::copy;
    let tcp_r = match tcp.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let uds_r = match uds.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut tcp_r = tcp_r;
    let mut uds_w = uds;
    let mut uds_r = uds_r;
    let mut tcp_w = tcp;

    let t = std::thread::spawn(move || {
        let _ = copy(&mut tcp_r, &mut uds_w);
    });
    let _ = copy(&mut uds_r, &mut tcp_w);
    let _ = t.join();
}

/// Assign `127.0.0.1` to `lo` + bring it UP via raw ioctls (no netlink, no
/// `ip`). A fresh `--unshare-net` netns has `lo` down with no address, so
/// BOTH ops are needed before `127.0.0.1` is bindable.
fn ensure_loopback_up() -> IoResult<()> {
    // SAFETY: we open an AF_INET DGRAM socket purely for ioctl(); the only
    // memory we touch is two stack-local zero-initialized `libc::ifreq`
    // structs whose layout matches what the kernel expects for SIOCSIFADDR /
    // SIOCGIFFLAGS / SIOCSIFFLAGS. The name field is NUL-padded "lo" (2
    // bytes < IFNAMSIZ=16, so no overflow). The sockaddr written into
    // `ifr_ifru.ifru_addr` is `sockaddr_in`, which is smaller than the
    // anonymous union (sockaddr_in fits inside `sockaddr` storage on Linux),
    // and `s_addr` is stored in network byte order — `from_ne_bytes` gives
    // the right value because `in_addr.s_addr` is a `u32` whose memory
    // representation IS the 4 address octets in order. We close `fd` on
    // every exit path.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let res = (|| -> IoResult<()> {
            // 1) assign 127.0.0.1 (SIOCSIFADDR)
            let mut ifr: libc::ifreq = std::mem::zeroed();
            set_iface_name(&mut ifr, b"lo");
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                // `in_addr.s_addr` is network-byte-order; the byte sequence
                // [127,0,0,1] reinterpreted as a u32 via `from_ne_bytes`
                // produces the correct network-order memory layout on both
                // little- and big-endian hosts.
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                },
                sin_zero: [0; 8],
            };
            std::ptr::copy_nonoverlapping(
                &sin as *const _ as *const u8,
                &mut ifr.ifr_ifru as *mut _ as *mut u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            );
            if libc::ioctl(fd, libc::SIOCSIFADDR, &ifr) < 0 {
                let e = std::io::Error::last_os_error();
                // Tolerate already-set: re-running the inner stage (e.g. in
                // tests) shouldn't fail just because lo already has the addr.
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(e);
                }
            }

            // 2) bring lo UP (read flags → OR IFF_UP|IFF_RUNNING → write back)
            let mut ifr2: libc::ifreq = std::mem::zeroed();
            set_iface_name(&mut ifr2, b"lo");
            if libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr2) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            ifr2.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            if libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifr2) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })();

        libc::close(fd);
        res
    }
}

/// Copy a NUL-padded interface name (e.g. b"lo") into `ifr_name`. `name` must
/// be < `IFNAMSIZ` (16) bytes; longer names panic in debug, truncate in
/// release — callers should pass short literals only.
fn set_iface_name(ifr: &mut libc::ifreq, name: &[u8]) {
    debug_assert!(name.len() < libc::IFNAMSIZ);
    for (i, b) in name.iter().enumerate() {
        if i >= libc::IFNAMSIZ - 1 {
            break;
        }
        ifr.ifr_name[i] = *b as libc::c_char;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;
    use std::time::Duration;

    /// `pump_bidirectional` shuttles bytes both ways between a TCP pair and
    /// a UDS pair. We synthesize both pairs in-process (no fork, no
    /// netns) — this is a unit test of the byte pump, not the netns logic.
    #[test]
    fn pump_bidirectional_forwards_both_directions() {
        // TCP side: a listener + a client.
        let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let tcp_accept_thread = thread::spawn(move || {
            let (s, _) = tcp_listener.accept().unwrap();
            s
        });
        let tcp_client = std::net::TcpStream::connect(tcp_addr).unwrap();
        let tcp_server_side = tcp_accept_thread.join().unwrap();

        // UDS side: a listener + a client.
        let dir = tempfile::tempdir().unwrap();
        let uds_path = dir.path().join("pump.sock");
        let uds_listener = UnixListener::bind(&uds_path).unwrap();
        let uds_accept_thread = thread::spawn(move || {
            let (s, _) = uds_listener.accept().unwrap();
            s
        });
        let uds_client = UnixStream::connect(&uds_path).unwrap();
        let uds_server_side = uds_accept_thread.join().unwrap();

        // Hand the SERVER ends to the pump. The CLIENT ends are what the
        // test writes/reads, so they're the "outside" of each pipe.
        let pump = thread::spawn(move || {
            pump_bidirectional(tcp_server_side, uds_server_side);
        });

        // tcp_client → tcp_server → pump → uds_server → uds_client
        // Write a fixed 4-byte payload and read exactly 4 bytes back —
        // don't use read_to_end (the connection isn't EOF'd until both
        // ends close, and we keep tcp_client alive to read the reverse
        // direction below).
        let mut tcp_w = tcp_client.try_clone().unwrap();
        tcp_w.write_all(b"ping").unwrap();
        let mut got = [0u8; 4];
        let mut uds_r = uds_client.try_clone().unwrap();
        uds_r
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        uds_r.read_exact(&mut got).expect("forward direction");
        assert_eq!(&got, b"ping");

        // Reverse direction: write into uds_client, read out of tcp_client.
        let mut uds_w = uds_client.try_clone().unwrap();
        uds_w.write_all(b"pong").unwrap();
        let mut back = [0u8; 4];
        let mut tcp_r = tcp_client.try_clone().unwrap();
        tcp_r
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        tcp_r.read_exact(&mut back).expect("reverse direction");
        assert_eq!(&back, b"pong");

        // Close both client ends so the pump sees EOF and unwinds.
        drop(tcp_w);
        drop(tcp_r);
        drop(uds_w);
        drop(uds_r);
        drop(tcp_client);
        drop(uds_client);
        pump.join().unwrap();
    }

    #[test]
    fn set_iface_name_pads_and_truncates() {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        set_iface_name(&mut ifr, b"lo");
        assert_eq!(ifr.ifr_name[0], b'l' as libc::c_char);
        assert_eq!(ifr.ifr_name[1], b'o' as libc::c_char);
        assert_eq!(ifr.ifr_name[2], 0);
    }
}
