//! The host naming ladder, end to end through the real discovery write path.
//!
//! GH #680: a UniFi switch imported under a name the administrator chose, and a rescan that both
//! keeps that name fresh and leaves a hand-typed one alone. The interesting behaviour is not in
//! any single function — it is what survives two consecutive `discover_host` calls with an
//! interleaved user edit, which is exactly what `upsert_host` used to get wrong by having no
//! `name` merge arm at all.

use std::net::{IpAddr, Ipv4Addr};

use uuid::Uuid;

use crate::server::auth::middleware::auth::AuthenticatedEntity;
use crate::server::hosts::r#impl::api::{HostResponse, UpdateHostRequest};
use crate::server::hosts::r#impl::base::{Host, HostBase};
use crate::server::hosts::r#impl::name::{HostName, HostNameSource};
use crate::server::interfaces::r#impl::base::InterfaceDataComplete;
use crate::server::ip_addresses::r#impl::base::{IPAddress, IPAddressBase};
use crate::server::networks::r#impl::{Network, NetworkBase};
use crate::server::shared::events::traits::Event;
use crate::server::shared::events::types::EntityOperation;
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
/// What reverse DNS answers for the device: DHCP registered the lease, so the record is an FQDN.
const RESOLVED_HOSTNAME: &str = "nas.lan.example.com";
/// What the same device advertised to DHCP, and therefore what a controller reports for it: the
/// bare label. Differing from the PTR is the ordinary case, not a contrived one.
const ADVERTISED_HOSTNAME: &str = "nas";

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
        cidr: LAN_CIDR.parse().unwrap(),
        subnet_type: SubnetType::Lan,
        source: EntitySource::Discovery,
        ..Default::default()
    });

    let ip = IPAddress::new(IPAddressBase {
        network_id,
        host_id: host.id,
        subnet_id: subnet.id,
        ip_address: device_ip,
        mac_address: DEVICE_MAC.parse().ok(),
        name: None,
        position: 0,
    });

    Submission {
        host,
        ip_address: ip,
        subnet,
    }
}

/// The same host as a controller reports one of its clients: the hostname is the name the client
/// advertised to DHCP, which the controller heard rather than read off the host.
fn client_submission(network_id: Uuid, name: HostName, hostname: &str) -> Submission {
    let mut s = submission(network_id, name, Some(hostname));
    s.host.base.hostname_authoritative = false;
    s
}

/// A *separate* host carrying a second-hand hostname: its own address and its own MAC, so
/// discovery keeps it apart from the device at [`DEVICE_IP`] and the only way the two ever meet is
/// a consolidation somebody asked for.
fn second_hand_host(network_id: Uuid) -> Submission {
    let mut s = submission_at(
        network_id,
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 21)),
        HostName::Hostname(ADVERTISED_HOSTNAME.to_string()),
        Some(ADVERTISED_HOSTNAME),
    );
    s.host.base.hostname_authoritative = false;
    s.ip_address.base.mac_address = "aa:bb:cc:00:00:21".parse().ok();
    s
}

/// Merge `source` into `destination`, the way the consolidate endpoint does: both hosts read back
/// out of storage first, which is precisely where the provenance of a hostname is lost.
async fn consolidate(
    services: &ServiceFactory,
    destination: &HostResponse,
    source: &HostResponse,
) -> HostResponse {
    let destination_host = services
        .host_service
        .get_by_id(&destination.id)
        .await
        .unwrap()
        .expect("the destination host must still exist");
    let other_host = services
        .host_service
        .get_by_id(&source.id)
        .await
        .unwrap()
        .expect("the host being merged away must still exist");

    services
        .host_service
        .consolidate_hosts(destination_host, other_host, AuthenticatedEntity::System)
        .await
        .expect("the consolidation must succeed")
}

struct Submission {
    host: Host,
    ip_address: IPAddress,
    subnet: Subnet,
}

/// Every `Updated` event published for `host_id` since the receiver was taken, as their
/// `trigger_stale` flags.
///
/// `upsert_host` is the only publisher of a host `Updated` event on the discovery write path, and
/// it publishes only when it decided something actually changed — so an empty list here *is* the
/// assertion that the merge found nothing to do.
///
/// Which is exactly why a dropped event may not pass silently: these tests assert on the *absence*
/// of updates, and a receiver that fell behind would report an empty list for a host that flipped
/// on every cycle — the failure mode under test, reported as the fix. The channel holds 1000 and
/// no test here publishes a handful, so `Lagged` is unreachable today; the arm is what keeps it
/// that way if either of those changes.
fn updates_for(
    events: &mut tokio::sync::broadcast::Receiver<Event<EntityOperation>>,
    host_id: Uuid,
) -> Vec<bool> {
    use tokio::sync::broadcast::error::TryRecvError;

    let mut seen = Vec::new();
    loop {
        match events.try_recv() {
            Ok(event) => {
                if event.scope.entity_id() == host_id
                    && matches!(event.operation, EntityOperation::Updated)
                {
                    seen.push(event.flags.trigger_stale);
                }
            }
            Err(TryRecvError::Empty | TryRecvError::Closed) => return seen,
            Err(TryRecvError::Lagged(dropped)) => {
                panic!(
                    "the event receiver fell behind and dropped {dropped} events; this assertion \
                     counts updates, so a silent drop would report a flapping host as a quiet one"
                )
            }
        }
    }
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
        submission(network_id, HostName::Ip(DEVICE_IP), None),
    )
    .await;
    assert_eq!(scanned.name, DEVICE_IP.to_string());

    let synced = submit(
        &services,
        submission(
            network_id,
            HostName::Integration("Core Switch".to_string()),
            None,
        ),
    )
    .await;

    assert_eq!(synced.id, scanned.id, "the same host, matched on its IP");
    assert_eq!(synced.name, "Core Switch");
    assert_eq!(synced.name_source, HostNameSource::Integration);
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
            HostName::Integration("Floor 1 Switch".to_string()),
            None,
        ),
    )
    .await;

    let renamed = submit(
        &services,
        submission(
            network_id,
            HostName::Integration("Floor 2 Switch".to_string()),
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
        submission(
            network_id,
            HostName::Integration("Core Switch".to_string()),
            None,
        ),
    )
    .await;

    let typed = save_from_ui(&services, &discovered, "Rack 3 Top Switch", false).await;
    assert_eq!(typed.name_source, HostNameSource::Manual);

    let resynced = submit(
        &services,
        submission(
            network_id,
            HostName::Integration("Core Switch Renamed Upstream".to_string()),
            Some("switch.lan"),
        ),
    )
    .await;

    assert_eq!(
        resynced.name, "Rack 3 Top Switch",
        "a later sync must not overwrite a name a person typed"
    );
    assert_eq!(resynced.name_source, HostNameSource::Manual);
}

/// The edit modal PUTs every field, so "the user saved the host" cannot be read as "the user
/// named the host" — otherwise toggling `hidden` once would freeze the name for good.
#[tokio::test]
async fn saving_an_unrelated_field_does_not_freeze_a_derived_name() {
    harness!(services, network_id, _container);

    let discovered = submit(
        &services,
        submission(network_id, HostName::Ip(DEVICE_IP), None),
    )
    .await;

    let hidden = save_from_ui(&services, &discovered, &discovered.name, true).await;
    assert!(hidden.hidden);
    assert_eq!(
        hidden.name_source,
        HostNameSource::Ip,
        "an unchanged name is not a user assertion about the name"
    );

    let synced = submit(
        &services,
        submission(
            network_id,
            HostName::Integration("Meeting Room AP".to_string()),
            None,
        ),
    )
    .await;
    assert_eq!(synced.name, "Meeting Room AP");
}

/// `Manual` means "a person typed this into Scanopy", which nothing on a daemon can know. A
/// payload claiming it is clamped, so the claim cannot lock the name against future syncs.
#[tokio::test]
async fn a_daemon_cannot_claim_a_name_was_typed_by_a_person() {
    harness!(services, network_id, _container);

    let mut forged = submission(
        network_id,
        HostName::Integration("Impostor".to_string()),
        None,
    );
    forged.host.base.name = HostName::Manual("Impostor".to_string());

    let created = submit(&services, forged).await;
    assert_eq!(created.name_source, HostNameSource::Integration);

    let resynced = submit(
        &services,
        submission(
            network_id,
            HostName::Integration("Real Name".to_string()),
            None,
        ),
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
            HostName::Integration("Meeting Room AP".to_string()),
            None,
        ),
    )
    .await;

    let rescanned = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname("unifi-a1b2c3.lan".to_string()),
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
        submission(network_id, HostName::Ip(DEVICE_IP), None),
    )
    .await;

    let mut legacy = submission(network_id, HostName::Unnamed, Some("nas.lan"));
    legacy.host.base.name = HostName::Unspecified("nas.lan".to_string());

    let upgraded = submit(&services, legacy).await;
    assert_eq!(upgraded.name, "nas.lan");
    assert_eq!(upgraded.name_source, HostNameSource::Hostname);
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
        submission_at(network_id, DEVICE_IP, HostName::Ip(DEVICE_IP), None),
    )
    .await;
    assert_eq!(first.name, "192.168.1.20");

    let moved_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 21));
    let moved = submit(
        &services,
        submission_at(network_id, moved_ip, HostName::Ip(moved_ip), None),
    )
    .await;

    assert_eq!(moved.id, first.id, "the same host, matched on its MAC");
    assert_eq!(
        moved.name, "192.168.1.21",
        "an address-derived name must follow the address it was derived from"
    );
    assert_eq!(moved.name_source, HostNameSource::Ip);
}

/// GH #89: the hostname a host answers to is an observation, and observations are allowed to
/// change. A lab rebuild handed two devices each other's address; Scanopy re-matched onto the
/// existing rows and they went on displaying the previous devices' names, because `hostname` was
/// written once at creation and the display name is re-derived from that same field.
///
/// Both halves have to move together, which is why this asserts both: the display name is
/// re-applied from the *stored* hostname after the incoming name, so a stale hostname does not
/// merely fail to update the name — it overwrites the fresh candidate with the old one.
#[tokio::test]
async fn a_host_that_reports_a_new_hostname_stops_wearing_the_old_one() {
    harness!(services, network_id, _container);

    let first = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname("leaf1.lab".to_string()),
            Some("leaf1.lab"),
        ),
    )
    .await;
    assert_eq!(first.hostname.as_deref(), Some("leaf1.lab"));
    assert_eq!(first.name, "leaf1.lab");

    let rebuilt = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname("leaf2.lab".to_string()),
            Some("leaf2.lab"),
        ),
    )
    .await;

    assert_eq!(rebuilt.id, first.id, "the same host, matched on its MAC");
    assert_eq!(
        rebuilt.name, "leaf2.lab",
        "a name re-derived from a frozen hostname freezes with it, and the host goes on wearing \
         another device's label"
    );
    assert_eq!(rebuilt.name_source, HostNameSource::Hostname);
    assert_eq!(
        rebuilt.hostname.as_deref(),
        Some("leaf2.lab"),
        "the hostname is what the host answers to now, not what it answered to first"
    );
}

/// Absence of evidence is not evidence of absence. A scan that could not resolve a hostname —
/// no reverse lookup, no SNMP sysName — says nothing about the name, so it must leave both the
/// recorded hostname and the name derived from it exactly where they were.
#[tokio::test]
async fn a_scan_that_resolved_no_hostname_leaves_the_recorded_one_alone() {
    harness!(services, network_id, _container);

    let named = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname("nas.lan".to_string()),
            Some("nas.lan"),
        ),
    )
    .await;
    assert_eq!(named.hostname.as_deref(), Some("nas.lan"));
    assert_eq!(named.name, "nas.lan");

    let rescanned = submit(
        &services,
        submission(network_id, HostName::Ip(DEVICE_IP), None),
    )
    .await;

    assert_eq!(rescanned.id, named.id, "the same host, matched on its MAC");
    assert_eq!(
        rescanned.hostname.as_deref(),
        Some("nas.lan"),
        "a scan with nothing to say about the hostname must not erase it"
    );
    assert_eq!(rescanned.name, "nas.lan");
    assert_eq!(rescanned.name_source, HostNameSource::Hostname);
}

/// A blank hostname on the wire is the same non-statement as an absent one — an empty column, a
/// reverse lookup that returned nothing but whitespace — and must not overwrite a real value.
#[tokio::test]
async fn a_blank_hostname_is_not_an_observation() {
    harness!(services, network_id, _container);

    let named = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname("nas.lan".to_string()),
            Some("nas.lan"),
        ),
    )
    .await;

    let rescanned = submit(
        &services,
        submission(network_id, HostName::Ip(DEVICE_IP), Some("   ")),
    )
    .await;

    assert_eq!(rescanned.id, named.id, "the same host, matched on its MAC");
    assert_eq!(rescanned.hostname.as_deref(), Some("nas.lan"));
    assert_eq!(rescanned.name, "nas.lan");
}

/// Refreshing the hostname must not lower the bar for the display name: the fresh hostname is
/// *offered* to the ladder, and a name a person typed still outranks it.
#[tokio::test]
async fn a_refreshed_hostname_does_not_displace_a_hand_typed_name() {
    harness!(services, network_id, _container);

    let discovered = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname("leaf1.lab".to_string()),
            Some("leaf1.lab"),
        ),
    )
    .await;

    let typed = save_from_ui(&services, &discovered, "Rack 3 Leaf", false).await;
    assert_eq!(typed.name_source, HostNameSource::Manual);

    let rebuilt = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname("leaf2.lab".to_string()),
            Some("leaf2.lab"),
        ),
    )
    .await;

    assert_eq!(
        rebuilt.name, "Rack 3 Leaf",
        "a hostname that changed is still below a name a person typed"
    );
    assert_eq!(rebuilt.name_source, HostNameSource::Manual);
    assert_eq!(
        rebuilt.hostname.as_deref(),
        Some("leaf2.lab"),
        "the observation is still recorded — it just does not win the display name"
    );
}

/// GH #89, the other half: once a hostname may be rewritten, two discovery paths that both report
/// one have to be told apart, or they take turns.
///
/// A UniFi site submits the same host twice per cycle — the sweep, whose hostname is reverse DNS,
/// and the client record, whose hostname is what the client advertised to DHCP. Wherever DHCP
/// registered the lease in DNS the two strings differ by the domain, so an unqualified
/// "last writer wins" has them overwriting each other for ever: the hostname flips, the display
/// name flips with it (a client with no controller alias is named at the same `Hostname` rung),
/// and every flip sets `trigger_stale`, forcing a topology rebuild every cycle for the largest
/// host population on the network.
///
/// So this runs both submissions, in both orders, twice, and asserts the row is *quiet*: same
/// hostname, same display name, and not one update event after the first cycle settles it.
#[tokio::test]
async fn a_sweep_and_a_controller_client_do_not_take_turns_renaming_one_host() {
    harness!(services, network_id, _container);

    let swept = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname(RESOLVED_HOSTNAME.to_string()),
            Some(RESOLVED_HOSTNAME),
        ),
    )
    .await;
    assert_eq!(swept.hostname.as_deref(), Some(RESOLVED_HOSTNAME));
    assert_eq!(swept.name, RESOLVED_HOSTNAME);

    // Subscribe only now: the host's creation is not what is under test.
    let mut events = services.event_bus.entity_channel.subscribe_channel();

    let mut observed = Vec::new();
    for _ in 0..2 {
        let from_controller = submit(
            &services,
            client_submission(
                network_id,
                HostName::Hostname(ADVERTISED_HOSTNAME.to_string()),
                ADVERTISED_HOSTNAME,
            ),
        )
        .await;
        observed.push(from_controller);

        let from_sweep = submit(
            &services,
            submission(
                network_id,
                HostName::Hostname(RESOLVED_HOSTNAME.to_string()),
                Some(RESOLVED_HOSTNAME),
            ),
        )
        .await;
        observed.push(from_sweep);
    }

    for (i, host) in observed.iter().enumerate() {
        assert_eq!(host.id, swept.id, "every submission is the same host");
        assert_eq!(
            host.hostname.as_deref(),
            Some(RESOLVED_HOSTNAME),
            "submission {i}: the hostname a scan resolved from the host owns the field; a name a \
             controller heard second-hand must not take it back"
        );
        assert_eq!(
            host.name, RESOLVED_HOSTNAME,
            "submission {i}: the display name is re-derived from that field, so it flips with it"
        );
        assert_eq!(host.name_source, HostNameSource::Hostname);
    }

    assert!(
        updates_for(&mut events, swept.id).is_empty(),
        "nothing about the host changed across two cycles, so the merge must publish no update \
         at all — every one of them would carry trigger_stale and rebuild the topology"
    );
}

/// The other order, and the reason the rule is "may not rewrite" rather than "is ignored": a
/// client the sweep cannot reach is a host the controller is the only witness for, and the name
/// it advertised to DHCP is all there is. It fills an empty field, and yields the moment a scan
/// resolves one.
#[tokio::test]
async fn a_hostname_only_a_controller_heard_still_fills_an_empty_field() {
    harness!(services, network_id, _container);

    let from_controller = submit(
        &services,
        client_submission(
            network_id,
            HostName::Hostname(ADVERTISED_HOSTNAME.to_string()),
            ADVERTISED_HOSTNAME,
        ),
    )
    .await;
    assert_eq!(
        from_controller.hostname.as_deref(),
        Some(ADVERTISED_HOSTNAME)
    );
    assert_eq!(from_controller.name, ADVERTISED_HOSTNAME);

    let swept = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname(RESOLVED_HOSTNAME.to_string()),
            Some(RESOLVED_HOSTNAME),
        ),
    )
    .await;

    assert_eq!(
        swept.id, from_controller.id,
        "the same host, matched on its MAC"
    );
    assert_eq!(
        swept.hostname.as_deref(),
        Some(RESOLVED_HOSTNAME),
        "a hostname read off the host replaces one that was only reported"
    );
    assert_eq!(swept.name, RESOLVED_HOSTNAME);
}

/// A hostname that changed is still below a name a *controller* supplied, not just below one a
/// person typed — the two sit on different rungs and only the top one was covered.
#[tokio::test]
async fn a_refreshed_hostname_does_not_displace_a_controller_name() {
    harness!(services, network_id, _container);

    let named = submit(
        &services,
        submission(
            network_id,
            HostName::Integration("Meeting Room AP".to_string()),
            Some("ap1.lab"),
        ),
    )
    .await;
    assert_eq!(named.name, "Meeting Room AP");

    let rebuilt = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname("ap2.lab".to_string()),
            Some("ap2.lab"),
        ),
    )
    .await;

    assert_eq!(rebuilt.id, named.id, "the same host, matched on its MAC");
    assert_eq!(
        rebuilt.name, "Meeting Room AP",
        "reverse DNS sits below a controller's name, refreshed or not"
    );
    assert_eq!(rebuilt.name_source, HostNameSource::Integration);
    assert_eq!(
        rebuilt.hostname.as_deref(),
        Some("ap2.lab"),
        "the observation is still recorded — it just does not win the display name"
    );
}

/// A rescan that reports exactly what is already stored must be silent. It matters more now that
/// the hostname can change at all: `hostname` is a topology-staleness trigger, so a merge that
/// reports a change it did not make rebuilds the topology on every cycle.
#[tokio::test]
async fn a_rescan_that_reports_the_same_hostname_publishes_no_update() {
    harness!(services, network_id, _container);

    let first = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname(RESOLVED_HOSTNAME.to_string()),
            Some(RESOLVED_HOSTNAME),
        ),
    )
    .await;

    let mut events = services.event_bus.entity_channel.subscribe_channel();

    let again = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname(RESOLVED_HOSTNAME.to_string()),
            Some(RESOLVED_HOSTNAME),
        ),
    )
    .await;
    assert_eq!(again.id, first.id);

    assert!(
        updates_for(&mut events, first.id).is_empty(),
        "an unchanged hostname is not an update, and an update here means a topology rebuild"
    );
}

/// Blankness was already judged on the trimmed value; the value itself was stored as it arrived.
/// Reverse DNS and SNMP sysName do not normalise, so a padded answer became a padded column and,
/// re-derived a few lines later, a padded display name.
#[tokio::test]
async fn a_padded_hostname_is_stored_trimmed() {
    harness!(services, network_id, _container);

    let created = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname(RESOLVED_HOSTNAME.to_string()),
            Some("  nas.lan.example.com  "),
        ),
    )
    .await;
    assert_eq!(
        created.hostname.as_deref(),
        Some(RESOLVED_HOSTNAME),
        "padding is not part of the name the host answers to"
    );
    assert_eq!(created.name, RESOLVED_HOSTNAME);

    let mut events = services.event_bus.entity_channel.subscribe_channel();

    // And the same value with different padding is the same observation, not a change.
    let again = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname(RESOLVED_HOSTNAME.to_string()),
            Some(" nas.lan.example.com"),
        ),
    )
    .await;
    assert_eq!(again.id, created.id);
    assert_eq!(again.hostname.as_deref(), Some(RESOLVED_HOSTNAME));
    assert!(
        updates_for(&mut events, created.id).is_empty(),
        "re-reporting the same hostname with different whitespace is not a change"
    );
}

/// GH #89, third face of the same field: a merge is not an observation.
///
/// `consolidate_hosts` loads both hosts out of the database and hands the source to the very merge
/// discovery uses. But the flag qualifies a payload and is not a column, so `Host::from_row`
/// reports every stored hostname as directly observed — true of the row being merged *into*, and
/// merely unknown for the row being merged *away*. Left unqualified, a hostname the network only
/// ever heard second-hand overwrites one a scan resolved off the destination host itself, purely
/// by being on the source side of a manual merge.
#[tokio::test]
async fn consolidating_a_host_cannot_overwrite_a_resolved_hostname_with_a_second_hand_one() {
    harness!(services, network_id, _container);

    let destination = submit(
        &services,
        submission(
            network_id,
            HostName::Hostname(RESOLVED_HOSTNAME.to_string()),
            Some(RESOLVED_HOSTNAME),
        ),
    )
    .await;
    assert_eq!(destination.hostname.as_deref(), Some(RESOLVED_HOSTNAME));

    // A second host: its own address and its own MAC, so discovery does not fold the two together
    // on its own and the merge under test is the one a person asks for.
    let source = submit(&services, second_hand_host(network_id)).await;
    assert_ne!(
        source.id, destination.id,
        "the two must start as separate hosts, or the merge under test never happens"
    );
    assert_eq!(source.hostname.as_deref(), Some(ADVERTISED_HOSTNAME));

    let merged = consolidate(&services, &destination, &source).await;

    assert_eq!(merged.id, destination.id);
    assert_eq!(
        merged.hostname.as_deref(),
        Some(RESOLVED_HOSTNAME),
        "the destination's hostname was resolved off the host; the source's was only ever \
         reported, and persisting it does not turn it into an observation"
    );
    assert_eq!(
        merged.name, RESOLVED_HOSTNAME,
        "the display name is re-derived from that field, so it goes wherever the hostname goes"
    );
}

/// The other half of the same rule, so the fix above stays a rule and does not become "the merge
/// ignores the source". A destination with no hostname has nothing to defend, and the host being
/// merged away is the only thing that knows what it answered to.
#[tokio::test]
async fn consolidating_a_host_still_fills_an_empty_hostname() {
    harness!(services, network_id, _container);

    let destination = submit(
        &services,
        submission(network_id, HostName::Ip(DEVICE_IP), None),
    )
    .await;
    assert_eq!(destination.hostname, None);

    let source = submit(&services, second_hand_host(network_id)).await;

    let merged = consolidate(&services, &destination, &source).await;

    assert_eq!(merged.id, destination.id);
    assert_eq!(
        merged.hostname.as_deref(),
        Some(ADVERTISED_HOSTNAME),
        "an empty field has nothing to defend, and a reported hostname beats none at all"
    );
    assert_eq!(merged.name, ADVERTISED_HOSTNAME);
}
