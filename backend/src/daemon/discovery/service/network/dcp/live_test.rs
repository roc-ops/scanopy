//! Round-trips a real DCP Identify exchange over a real raw-socket pair — a veth pair created by
//! `tools/dcp/dcp-test-env.sh`, which the unit tests in `packet.rs`/`identify.rs` cannot exercise
//! since they run entirely in memory. Proves our own encoder against our own decoder over the
//! actual kernel/NIC-driver path (real EtherType/multicast filtering, real byte order on the
//! wire) — not proof of interop with a real PROFINET device. See `tools/dcp/DCP-TEST-ENV.md` for
//! that honest limit.
//!
//! Ignored by default — needs root/CAP_NET_ADMIN and a real veth pair, neither of which a normal
//! `cargo test --lib` run has:
//!
//!   sudo tools/dcp/dcp-test-env.sh up
//!   cd backend && cargo test --lib -- --ignored dcp_live
//!   sudo tools/dcp/dcp-test-env.sh down
//!
//! Unverified by this session: never run (this sandbox is macOS, no `ip netns`/veth support and
//! no root) — see the Work Summary.

#![cfg(test)]

use std::time::{Duration, Instant};

use pnet::datalink;
use pnet::packet::Packet;

use super::channel::{DcpChannel, PnetDcpChannel};
use super::identify::scan_interface;

const IFACE_A: &str = "dcp-test-a";
const IFACE_B: &str = "dcp-test-b";

const FRAME_ID_DCP_IDENT_REQ: u16 = 0xFEFE;
const FRAME_ID_DCP_IDENT_RES: u16 = 0xFEFF;

/// A minimal stand-in for a real PROFINET device: waits for an Identify Request on `IFACE_B`
/// and answers it, echoing the request's `Xid`. Deliberately not sharing code with
/// `packet::build_identify_request`/`parse_identify_response` (which build/parse the *daemon's*
/// side of the exchange) — a device building its own reply is a different role, and duplicating
/// a dozen lines here keeps that distinction visible rather than repurposing the client's own
/// encoder to play the server.
fn respond_once(channel: &mut impl DcpChannel, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        let Ok(Some(frame)) = channel.recv() else {
            continue;
        };
        let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(&frame) else {
            continue;
        };
        if eth.get_ethertype()
            != pnet::packet::ethernet::EtherType::new(super::packet::ETHERTYPE_PROFINET)
        {
            continue;
        }
        let payload = eth.payload();
        if payload.len() < 12 {
            continue;
        }
        let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
        if frame_id != FRAME_ID_DCP_IDENT_REQ {
            continue;
        }
        let xid = [payload[4], payload[5], payload[6], payload[7]];

        let mut response = vec![0u8; 14];
        {
            use pnet::packet::ethernet::MutableEthernetPacket;
            let mut resp_eth = MutableEthernetPacket::new(&mut response).unwrap();
            resp_eth.set_destination(eth.get_source());
            resp_eth.set_source(eth.get_destination()); // stand-in "device" address
            resp_eth.set_ethertype(pnet::packet::ethernet::EtherType::new(
                super::packet::ETHERTYPE_PROFINET,
            ));
        }
        response.extend_from_slice(&FRAME_ID_DCP_IDENT_RES.to_be_bytes());
        response.push(0x05); // ServiceID: Identify
        response.push(0x01); // ServiceType: ResponseSuccess
        response.extend_from_slice(&xid);
        response.extend_from_slice(&0u16.to_be_bytes()); // reserved
        response.extend_from_slice(&0u16.to_be_bytes()); // no blocks

        let _ = channel.send(&response);
        return true;
    }
    false
}

#[test]
#[ignore = "needs a real veth pair and raw-socket privileges; see tools/dcp/dcp-test-env.sh"]
fn dcp_live_round_trip_over_a_real_veth_pair() {
    let interfaces = datalink::interfaces();
    let iface_a = interfaces
        .iter()
        .find(|i| i.name == IFACE_A)
        .unwrap_or_else(|| panic!("{IFACE_A} not found — run tools/dcp/dcp-test-env.sh up"))
        .clone();
    let iface_b = interfaces
        .iter()
        .find(|i| i.name == IFACE_B)
        .unwrap_or_else(|| panic!("{IFACE_B} not found — run tools/dcp/dcp-test-env.sh up"))
        .clone();

    let responder = std::thread::spawn(move || {
        let mut channel = PnetDcpChannel::open(&iface_b, Duration::from_millis(100))
            .expect("open the responder side of the veth pair");
        respond_once(&mut channel, Instant::now() + Duration::from_secs(5))
    });

    // Give the responder thread a moment to be listening before the client sends.
    std::thread::sleep(Duration::from_millis(200));

    let found = scan_interface(&iface_a).expect("scan the client side of the veth pair");
    let responded = responder.join().expect("responder thread panicked");

    assert!(responded, "the stand-in device never saw a request");
    assert!(
        !found.is_empty(),
        "the real round trip over the veth pair produced no result"
    );
}
