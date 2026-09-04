//! The host naming ladder, end to end through the real discovery write path.
//!
//! GH #680: a UniFi switch imported under a name the administrator chose, and a rescan that both
//! keeps that name fresh and leaves a hand-typed one alone. The interesting behaviour is not in
//! any single function — it is what survives two consecutive `discover_host` calls with an
//! interleaved user edit, which is exactly what `upsert_host` used to get wrong by having no
//! `name` merge arm at all.

use crate::server::ip_addresses::r#impl::base::{MacEvidence, MacEvidenceValue};
use crate::server::shared::attribution::AttributeSource;
use std::net::{IpAddr, Ipv4Addr};

use uuid::Uuid;

use crate::server::auth::middleware::auth::AuthenticatedEntity;
use crate::server::hosts::r#impl::api::{HostResponse, UpdateHostRequest};
use crate::server::hosts::r#impl::base::{Host, HostBase};
use crate::server::hosts::r#impl::name::{HostName, HostNameSources};
use crate::server::services::r#impl::patterns::ClientProbe;
use crate::server::subnets::r#impl::base::{SubnetCidr, SubnetCidrValue};

/// A name a person assigned in a controller, which is what the old `Integration` rung meant. Named
/// once so these tests read the same as they did before the ladder was generalised.
const CONTROLLER: AttributeSource = AttributeSource::Authored(ClientProbe::UnifiController);

/// A name a person assigned in a UniFi controller.
fn controller_name(name: String) -> HostName {
    HostName::from_controller(name, ClientProbe::UnifiController)
}
use crate::server::interfaces::r#impl::base::InterfaceDataComplete;
use crate::server::ip_addresses::r#impl::base::{IPAddress, IPAddressBase};
use crate::server::networks::r#impl::{Network, NetworkBase};
use crate::server::shared::services::factory::ServiceFactory;
use crate::server::shared::services::traits::CrudService;
use crate::server::shared::storage::traits::{Storable, Storage};
use crate::server::shared::types::entities::EntitySource;
use crate::server::subnets::r#impl::base::{Subnet, SubnetBase};
use crate::server::subnets::r#impl::types::SubnetType;

use super::{organization, test_services};

const LAN_CIDR: &str = "192.168.1.0/24";
const DEVICE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
/// The device's chassis MAC. Present because it is what makes a second submission resolve to the
/// same host: the daemon mints a fresh pending subnet id every scan, so IP+subnet does not match
/// across scans and the MAC is the stable anchor.
const DEVICE_MAC: &str = "aa:bb:cc:00:00:20";

macro_rules! harness {
    ($services:ident, $network_id:ident, $container:ident) => {
        let (storage, $services, $container) = test_services().await;

        let org = organization();
        storage.organizations.create(&org).await.unwrap();

        let network = $services
            .network_service
            .create(
                Network::new(NetworkBase::new(org.id)),
                AuthenticatedEntity::System,
            )
            .await
            .unwrap();
        let $network_id = network.id;
    };
}

/// One controller-reported device, as the daemon submits it: an address on a known subnet and a
/// name carrying the rung it came from.
fn submission(network_id: Uuid, name: HostName, hostname: Option<&str>) -> Submission {
    submission_at(network_id, DEVICE_IP, name, hostname)
}

/// The same, at an explicit address — for the case where a host's DHCP lease moves.
fn submission_at(
    network_id: Uuid,
    device_ip: IpAddr,
    name: HostName,
    hostname: Option<&str>,
) -> Submission {
    let mut host = Host::new(HostBase {
        network_id,
        source: EntitySource::Discovery,
        hostname: hostname.map(str::to_string),
        ..Default::default()
    });
    host.base.apply_name(name);

    let subnet = Subnet::new(SubnetBase {
        name: "lan".to_string(),
        network_id,
        cidr: SubnetCidr::new(
            SubnetCidrValue(LAN_CIDR.parse().unwrap()),
            AttributeSource::DaemonSelfReport,
        ),
        subnet_type: SubnetType::Lan,
        source: EntitySource::Discovery,
        ..Default::default()
    });

    let ip = IPAddress::new(IPAddressBase {
        network_id,
        host_id: host.id,
        subnet_id: subnet.id,
        ip_address: device_ip,
        mac_address: DEVICE_MAC
            .parse()
            .ok()
            .map(|m| MacEvidence::new(MacEvidenceValue(m), AttributeSource::ArpReply)),
        name: None,
        position: 0,
    });

    Submission {
        host,
        ip_address: ip,
        subnet,
    }
}

struct Submission {
    host: Host,
    ip_address: IPAddress,
    subnet: Subnet,
}

async fn submit(services: &ServiceFactory, s: Submission) -> HostResponse {
    services
        .host_service
        .discover_host(
            s.host,
            vec![s.ip_address],
            vec![],
            vec![],
            vec![],
            vec![s.subnet],
            true,
            InterfaceDataComplete::default(),
            None,
            AuthenticatedEntity::System,
            None,
        )
        .await
        .expect("a discovery submission must persist")
}

/// Rename the host the way the edit modal does: the whole object, every field present.
async fn save_from_ui(
    services: &ServiceFactory,
    existing: &HostResponse,
    name: &str,
    hidden: bool,
) -> HostResponse {
    services
        .host_service
        .update_from_request(
            UpdateHostRequest {
                id: existing.id,
                name: name.to_string(),
                hostname: existing.hostname.clone(),
                description: existing.description.clone(),
                virtualization_metadata: None,
                virtualization_service_id: None,
                hidden,
                tags: vec![],
                expected_updated_at: None,
                ip_addresses: None,
                ports: None,
                services: None,
                interfaces: None,
                credential_assignments: None,
            },
            AuthenticatedEntity::System,
        )
        .await
        .expect("the update must succeed")
}

/// The reported bug: the controller holds the name, the host displays its DHCP address.
#[tokio::test]
async fn a_controller_name_replaces_an_address_derived_one() {
    harness!(services, network_id, _container);

    let scanned = submit(
        &services,
        submission(network_id, HostName::from_ip(DEVICE_IP), None),
    )
    .await;
    assert_eq!(scanned.name, DEVICE_IP.to_string());

    let synced = submit(
        &services,
        submission(network_id, controller_name("Core Switch".to_string()), None),
    )
    .await;

    assert_eq!(synced.id, scanned.id, "the same host, matched on its IP");
    assert_eq!(synced.name, "Core Switch");
    assert_eq!(synced.name_source, CONTROLLER);
}

/// "Changing a device's name in the controller updates the Scanopy host on the next sync."
/// Equal rank has to win for this, which is the one direction a first-write-wins merge cannot go.
#[tokio::test]
async fn a_controller_rename_propagates_on_the_next_sync() {
    harness!(services, network_id, _container);

    submit(
        &services,
        submission(
            network_id,
            controller_name("Floor 1 Switch".to_string()),
            None,
        ),
    )
    .await;

    let renamed = submit(
        &services,
        submission(
            network_id,
            controller_name("Floor 2 Switch".to_string()),
            None,
        ),
    )
    .await;

    assert_eq!(renamed.name, "Floor 2 Switch");
}

/// "A host whose name was set by hand in Scanopy keeps that name across repeated discoveries."
#[tokio::test]
async fn a_hand_typed_name_survives_repeated_discovery() {
    harness!(services, network_id, _container);

    let discovered = submit(
        &services,
        submission(network_id, controller_name("Core Switch".to_string()), None),
    )
    .await;

    let typed = save_from_ui(&services, &discovered, "Rack 3 Top Switch", false).await;
    assert_eq!(typed.name_source, AttributeSource::Manual);

    let resynced = submit(
        &services,
        submission(
            network_id,
            controller_name("Core Switch Renamed Upstream".to_string()),
            Some("switch.lan"),
        ),
    )
    .await;

    assert_eq!(
        resynced.name, "Rack 3 Top Switch",
        "a later sync must not overwrite a name a person typed"
    );
    assert_eq!(resynced.name_source, AttributeSource::Manual);
}

/// The edit modal PUTs every field, so "the user saved the host" cannot be read as "the user
/// named the host" — otherwise toggling `hidden` once would freeze the name for good.
#[tokio::test]
async fn saving_an_unrelated_field_does_not_freeze_a_derived_name() {
    harness!(services, network_id, _container);

    let discovered = submit(
        &services,
        submission(network_id, HostName::from_ip(DEVICE_IP), None),
    )
    .await;

    let hidden = save_from_ui(&services, &discovered, &discovered.name, true).await;
    assert!(hidden.hidden);
    assert_eq!(
        hidden.name_source,
        AttributeSource::OwnAddress,
        "an unchanged name is not a user assertion about the name"
    );

    let synced = submit(
        &services,
        submission(
            network_id,
            controller_name("Meeting Room AP".to_string()),
            None,
        ),
    )
    .await;
    assert_eq!(synced.name, "Meeting Room AP");
}

/// `Manual` means "a person typed this into Scanopy", which nothing on a daemon can know. A
/// payload claiming it is refused, so the claim cannot lock the name against future syncs.
///
/// The refused claim lands at `Unspecified` rather than at the rung below `Manual`. The old
/// naming ladder demoted by rank, which meant picking the next rung down and asserting it; a
/// payload that lied about its provenance has told us nothing believable about where the name came
/// from, and `Unspecified` is what that means. The name itself survives either way, and — as the
/// second half of this test shows — the next real sync can still rename the host, which is the
/// behaviour the guard exists for.
#[tokio::test]
async fn a_daemon_cannot_claim_a_name_was_typed_by_a_person() {
    harness!(services, network_id, _container);

    let mut forged = submission(network_id, controller_name("Impostor".to_string()), None);
    forged.host.base.name = HostName::manual("Impostor".to_string());

    let created = submit(&services, forged).await;
    assert_eq!(created.name, "Impostor", "the name itself is kept");
    assert_eq!(created.name_source, AttributeSource::Unspecified);

    let resynced = submit(
        &services,
        submission(network_id, controller_name("Real Name".to_string()), None),
    )
    .await;
    assert_eq!(
        resynced.name, "Real Name",
        "a forged Manual claim must not make a name permanent"
    );
}

/// A plain scan of a host an integration already named must not undo that name — reverse DNS
/// sits below a controller's name on the ladder.
#[tokio::test]
async fn reverse_dns_does_not_displace_a_controller_name() {
    harness!(services, network_id, _container);

    submit(
        &services,
        submission(
            network_id,
            controller_name("Meeting Room AP".to_string()),
            None,
        ),
    )
    .await;

    let rescanned = submit(
        &services,
        submission(
            network_id,
            HostName::from_hostname("unifi-a1b2c3.lan".to_string()),
            Some("unifi-a1b2c3.lan"),
        ),
    )
    .await;

    assert_eq!(rescanned.name, "Meeting Room AP");
    assert_eq!(
        rescanned.hostname.as_deref(),
        Some("unifi-a1b2c3.lan"),
        "the hostname is still recorded — it just does not win the display name"
    );
}

/// The pre-0.17.12 daemon case: no rank on the wire. Its name must not displace anything, but the
/// hostname it reports must still upgrade an address-derived name, exactly as it did before.
#[tokio::test]
async fn a_daemon_that_sends_no_rank_still_upgrades_an_address_to_its_hostname() {
    harness!(services, network_id, _container);

    submit(
        &services,
        submission(network_id, HostName::from_ip(DEVICE_IP), None),
    )
    .await;

    let mut legacy = submission(network_id, HostName::unnamed(), Some("nas.lan"));
    legacy.host.base.name = HostName::unattributed("nas.lan".to_string());

    let upgraded = submit(&services, legacy).await;
    assert_eq!(upgraded.name, "nas.lan");
    assert_eq!(upgraded.name_source, AttributeSource::ReverseDns);
}

/// A host matched by its MAC across a lease change adopts its new address as its name.
///
/// Distinct from the controller-rename case above: dedup resolves on the MAC rather than the
/// address, and the name that has to move is the address itself. Note this covers the *server*
/// half only — it asserts that an `Ip`-ranked candidate for a new address refreshes an
/// `Ip`-ranked name. The daemon-side half (the early ARP/ping stub declaring that rung at all,
/// `network/scan.rs`) sits inside the scan loop and is verified by rescanning the sim env, not
/// here.
#[tokio::test]
async fn an_address_derived_name_follows_the_host_to_a_new_address() {
    harness!(services, network_id, _container);

    let first = submit(
        &services,
        submission_at(network_id, DEVICE_IP, HostName::from_ip(DEVICE_IP), None),
    )
    .await;
    assert_eq!(first.name, "192.168.1.20");

    let moved_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 21));
    let moved = submit(
        &services,
        submission_at(network_id, moved_ip, HostName::from_ip(moved_ip), None),
    )
    .await;

    assert_eq!(moved.id, first.id, "the same host, matched on its MAC");
    assert_eq!(
        moved.name, "192.168.1.21",
        "an address-derived name must follow the address it was derived from"
    );
    assert_eq!(moved.name_source, AttributeSource::OwnAddress);
}
