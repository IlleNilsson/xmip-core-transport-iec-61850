//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): this transport held to how long Xmip takes — the millisecond rule
//! (`CONTRIBUTING.md`, *Rust is here for one reason*). A plain `cargo test`
//! leaves it out; the landing runs it after every other test of the module,
//! alone, one test at a time
//! (`cargo test --test measured --all-features -- --test-threads=1`), so
//! what is measured is Xmip's work and not its neighbors':
//!
//! - a thousand reads on one association take a millisecond each at most.

use std::time::{Duration, Instant};

use transport::Transport;
use xmip_core_transport_iec_61850::{Event, Iec61850Transport};

#[test]
fn a_thousand_reads_take_a_millisecond_each_at_most() {
    const RECEIVES: usize = 1000;
    let server = Iec61850Transport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(5));
    let (listener, address) = server.bind().expect("bind");
    let near = Iec61850Transport::new(&address).timing_out_after(Duration::from_secs(5));
    let reader = std::thread::spawn(move || {
        let began = Instant::now();
        for _ in 0..RECEIVES {
            assert_eq!(near.receive()?.remove(0).taken()?.bytes, b"held");
        }
        let took = began.elapsed();
        // Generous for a debug build under load: a millisecond a read.
        assert!(took < Duration::from_millis(RECEIVES as u64), "{took:?}");
        Ok::<_, transport::TransportError>(())
    });
    let mut session = server
        .accept_one(&listener)
        .expect("an association")
        .with_variable("XMIP", "Stream", b"held".to_vec());
    let mut read = 0;
    while read < RECEIVES {
        match session.next_event().expect("serving").expect("one") {
            Event::Initiated => {}
            Event::Read { served: true, .. } => read += 1,
            other => panic!("{other:?}"),
        }
    }
    reader.join().expect("thread").expect("reading");
}
