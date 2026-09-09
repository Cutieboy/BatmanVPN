use mousevpn_crypto::{
    ClientHandshake, CryptoError, KeyPair, ProtocolContext, ReplayError, ServerHandshake,
    REPLAY_WINDOW_SIZE,
};

fn establish() -> (
    mousevpn_crypto::SecureSession,
    mousevpn_crypto::SecureSession,
) {
    let client_keys = KeyPair::generate().expect("client key generation");
    let server_keys = KeyPair::generate().expect("server key generation");
    let context = ProtocolContext::for_server(&server_keys.public);

    let mut client = ClientHandshake::new(&client_keys.secret, &server_keys.public, &context)
        .expect("client handshake");
    let initial = client.write_initial(b"client hello").expect("initial");

    let mut server = ServerHandshake::new(&server_keys.secret, &context).expect("server handshake");
    let client_payload = server.read_initial(&initial).expect("read initial");
    assert_eq!(client_payload, b"client hello");
    assert_eq!(server.peer_static_key(), Some(client_keys.public));

    let (server_session, response) = server.finish(b"server hello").expect("response");
    let (client_session, server_payload) = client.finish(&response).expect("finish client");
    assert_eq!(server_payload, b"server hello");
    assert_eq!(client_session.peer_static_key(), server_keys.public);
    assert_eq!(server_session.peer_static_key(), client_keys.public);

    (client_session, server_session)
}

#[test]
fn encrypts_in_both_directions() {
    let (mut client, mut server) = establish();

    let request = client.encrypt(0, b"ping").expect("encrypt request");
    assert_eq!(
        server.decrypt(0, &request).expect("decrypt request"),
        b"ping"
    );

    let response = server.encrypt(0, b"pong").expect("encrypt response");
    assert_eq!(
        client.decrypt(0, &response).expect("decrypt response"),
        b"pong"
    );
}

#[test]
fn rejects_wrong_server_key() {
    let client_keys = KeyPair::generate().expect("client key generation");
    let server_keys = KeyPair::generate().expect("server key generation");
    let wrong_server_keys = KeyPair::generate().expect("wrong server key generation");
    let wrong_context = ProtocolContext::for_server(&wrong_server_keys.public);
    let server_context = ProtocolContext::for_server(&server_keys.public);

    let mut client = ClientHandshake::new(
        &client_keys.secret,
        &wrong_server_keys.public,
        &wrong_context,
    )
    .expect("client handshake");
    let initial = client.write_initial(&[]).expect("initial");
    let mut server =
        ServerHandshake::new(&server_keys.secret, &server_context).expect("server handshake");

    assert!(server.read_initial(&initial).is_err());
}

#[test]
fn rejects_tampering_without_poisoning_replay_window() {
    let (client, mut server) = establish();
    let valid = client.encrypt(50, b"authenticated").expect("encrypt");
    let mut tampered = valid.clone();
    tampered[0] ^= 1;

    assert!(server.decrypt(50, &tampered).is_err());
    assert_eq!(
        server.decrypt(50, &valid).expect("valid retry"),
        b"authenticated"
    );
}

#[test]
fn accepts_reordering_and_rejects_replays() {
    let (client, mut server) = establish();
    let earlier = client.encrypt(10, b"earlier").expect("encrypt earlier");
    let later = client.encrypt(11, b"later").expect("encrypt later");

    assert_eq!(server.decrypt(11, &later).expect("later first"), b"later");
    assert_eq!(
        server.decrypt(10, &earlier).expect("earlier second"),
        b"earlier"
    );
    assert!(matches!(
        server.decrypt(10, &earlier),
        Err(CryptoError::Replay(ReplayError::Duplicate))
    ));
}

#[test]
fn rejects_packets_older_than_window() {
    let (client, mut server) = establish();
    let old = client.encrypt(0, b"old").expect("encrypt old");
    let newest = client
        .encrypt(REPLAY_WINDOW_SIZE, b"new")
        .expect("encrypt newest");

    server
        .decrypt(REPLAY_WINDOW_SIZE, &newest)
        .expect("decrypt newest");
    assert!(matches!(
        server.decrypt(0, &old),
        Err(CryptoError::Replay(ReplayError::TooOld))
    ));
}

#[test]
fn burst_reordering_survives_and_forged_jumps_do_not_erase_replay_history() {
    let (client, server) = establish();
    let (send, _) = client.split();
    let (_, mut receive) = server.split();
    let mut earlier = vec![0; 128];
    let length = send.encrypt_into(1, b"delayed", &mut earlier).unwrap();
    earlier.truncate(length);
    let mut later = vec![0; 128];
    let length = send.encrypt_into(4_096, b"burst", &mut later).unwrap();
    later.truncate(length);
    let mut plaintext = vec![0; 128];
    receive.decrypt_into(4_096, &later, &mut plaintext).unwrap();
    // Changing an unauthenticated sequence must not clear any replay bits.
    assert!(receive
        .decrypt_into(1_000_000, &later, &mut plaintext)
        .is_err());
    let len = receive.decrypt_into(1, &earlier, &mut plaintext).unwrap();
    assert_eq!(&plaintext[..len], b"delayed");
    assert!(matches!(
        receive.decrypt_into(4_096, &later, &mut plaintext),
        Err(CryptoError::Replay(ReplayError::Duplicate)),
    ));
    assert!(matches!(
        receive.decrypt_into(1, &earlier, &mut plaintext),
        Err(CryptoError::Replay(ReplayError::Duplicate)),
    ));
}
