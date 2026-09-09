#[allow(dead_code, clippy::all, clippy::pedantic)]
#[path = "support/v2_reference.rs"]
mod old;

use mousevpn_morph::{DecodedFrame, Direction, MorphCodec, MorphError, MorphKey, Profile};

#[test]
fn old_and_new_codecs_interoperate_at_every_payload_length() {
    for (profile, old_profile) in [
        (Profile::Quiet, old::Profile::Quiet),
        (Profile::Balanced, old::Profile::Balanced),
        (Profile::Paranoid, old::Profile::Paranoid),
    ] {
        let new = MorphCodec::new(MorphKey::from_bytes([91; 32]), profile);
        let old = old::MorphCodec::new(old::MorphKey::from_bytes([91; 32]), old_profile);
        for (direction, old_direction) in [
            (Direction::ClientToServer, old::Direction::ClientToServer),
            (Direction::ServerToClient, old::Direction::ServerToClient),
        ] {
            let mut encoded = Vec::new();
            let mut decoded = Vec::new();
            // The v2 envelope costs 42 bytes; exercise padding clamping at 1472.
            for len in 0..=1_430 {
                let payload = vec![0xa5; len];
                new.encode_payload(&payload, direction, &mut encoded)
                    .unwrap();
                assert!((42 + len..=(73 + len).min(1_472)).contains(&encoded.len()));
                assert_eq!(
                    old.decode(&encoded, old_direction, &mut decoded).unwrap(),
                    old::DecodedFrame::Payload {
                        profile: old_profile
                    },
                );
                assert_eq!(decoded, payload);

                old.encode_payload(&payload, old_direction, &mut encoded)
                    .unwrap();
                assert_eq!(
                    new.decode(&encoded, direction, &mut decoded).unwrap(),
                    DecodedFrame::Payload { profile },
                );
                assert_eq!(decoded, payload);
            }
            new.encode_cover(direction, &mut encoded).unwrap();
            assert_eq!(
                old.decode(&encoded, old_direction, &mut decoded).unwrap(),
                old::DecodedFrame::Cover {
                    profile: old_profile
                },
            );
            assert!(decoded.is_empty());
            old.encode_cover(old_direction, &mut encoded).unwrap();
            assert_eq!(
                new.decode(&encoded, direction, &mut decoded).unwrap(),
                DecodedFrame::Cover { profile },
            );
            assert!(decoded.is_empty());
            assert!(matches!(
                new.encode_payload(&vec![0; 1_431], direction, &mut encoded),
                Err(MorphError::FrameTooLarge { .. }),
            ));
        }
    }
}

#[test]
fn tampered_old_frames_cannot_pass_the_new_decoder() {
    let old = old::MorphCodec::new(old::MorphKey::from_bytes([91; 32]), old::Profile::Balanced);
    let new = MorphCodec::new(MorphKey::from_bytes([91; 32]), Profile::Balanced);
    let mut encoded = Vec::new();
    old.encode_payload(
        b"authenticated data",
        old::Direction::ClientToServer,
        &mut encoded,
    )
    .unwrap();
    for byte in 0..encoded.len() {
        encoded[byte] ^= 1;
        assert!(new
            .decode(&encoded, Direction::ClientToServer, &mut Vec::new())
            .is_err());
        encoded[byte] ^= 1;
    }
}
