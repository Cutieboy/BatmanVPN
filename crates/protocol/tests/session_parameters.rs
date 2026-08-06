use std::net::Ipv4Addr;

use mousevpn_protocol::SessionParameters;

#[test]
fn session_parameters_round_trip() {
    let parameters = SessionParameters {
        client_address: Ipv4Addr::new(10, 77, 0, 2),
        prefix_len: 24,
        mtu: 1_280,
        dns: Ipv4Addr::new(1, 1, 1, 1),
    };

    assert_eq!(
        SessionParameters::decode(&parameters.encode()),
        Ok(parameters)
    );
}
