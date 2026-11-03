//! Tests for silent servers

use alloc::{boxed::Box, rc::Rc, sync::Arc, vec, vec::Vec};
use core::cell::RefCell;

use bytes::BytesMut;

use super::util::{
    IncomingConnectionBehavior, Pair, client_crypto_with_alpn, server_config,
    server_crypto_with_alpn, subscribe,
};
use crate::{
    ClientConfig, DatagramEvent, EndpointConfig, FourTuple, RandomConnectionIdGenerator, ServerConfig,
};

/// Enough ALPN protocols that the ClientHello spans two Initial packets.
fn alpns() -> Vec<Vec<u8>> {
    (0..16u8).map(|i| vec![b'a' + i; 100]).collect()
}

fn silent_pair() -> Pair {
    let mut config = ServerConfig::with_crypto(Arc::new(server_crypto_with_alpn(alpns())));
    config.silent(true);
    Pair::new(Arc::new(EndpointConfig::default()), config)
}

fn client_config() -> ClientConfig {
    ClientConfig::new(Arc::new(client_crypto_with_alpn(alpns())))
}

#[test]
fn silent_server_hands_over_the_whole_client_hello() {
    let _guard = subscribe();
    let mut pair = silent_pair();
    let seen = Rc::new(RefCell::new(None));
    let record = seen.clone();
    pair.server.handle_incoming = Box::new(move |incoming| {
        *record.borrow_mut() = incoming.client_hello().map(<[u8]>::len);
        IncomingConnectionBehavior::Accept
    });

    pair.connect_with(client_config());

    let len = seen.borrow().expect("the server saw the ClientHello");
    assert!(len > 1200, "a {len}-byte ClientHello fits in one Initial");
}

#[test]
fn silent_server_sends_nothing_to_attempts_it_ignores() {
    let _guard = subscribe();
    let mut pair = silent_pair();
    pair.server.handle_incoming = Box::new(|_| IncomingConnectionBehavior::Ignore);

    let client_ch = pair.begin_connect(client_config());
    for _ in 0..20 {
        pair.step();
    }

    let stats = pair.client_conn_mut(client_ch).stats();
    assert!(stats.udp_tx.datagrams > 0);
    assert_eq!(stats.udp_rx.datagrams, 0);
}

/// Packets a normal server answers: an unknown version, and a short-header
/// packet for an unknown connection.
fn probes() -> Vec<Vec<u8>> {
    let mut unknown_version = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8];
    unknown_version.extend([1; 8]);
    unknown_version.push(8);
    unknown_version.extend([2; 8]);
    unknown_version.resize(1200, 0);

    let mut unknown_connection = vec![0x40];
    unknown_connection.extend([3; 8]);
    unknown_connection.resize(100, 0x55);

    vec![unknown_version, unknown_connection]
}

#[test]
fn silent_server_answers_no_unauthenticated_packet() {
    let _guard = subscribe();
    for silent in [false, true] {
        let mut config = server_config();
        config.silent(silent);
        // Unlike the default, accepts any connection ID, so the probe gets as far as a reset.
        let mut endpoint = EndpointConfig::default();
        endpoint.cid_generator(Arc::new(|| Box::new(RandomConnectionIdGenerator::new(8))));
        let mut pair = Pair::new(Arc::new(endpoint), config);
        let from = FourTuple::from_remote("[::1]:4433".parse().unwrap());
        let mut buf = Vec::new();
        let replies = probes()
            .into_iter()
            .filter(|probe| {
                let event = pair.server.endpoint.handle(
                    pair.time,
                    from,
                    None,
                    BytesMut::from(&probe[..]),
                    &mut buf,
                );
                matches!(event, Some(DatagramEvent::Response(_)))
            })
            .count();
        let expected = if silent { 0 } else { probes().len() };
        assert_eq!(replies, expected, "silent: {silent}");
    }
}
