//! Translate UniFi wire shapes ([`super::types`]) into Scanopy entities.
//!
//! Pure and synchronous — no I/O — so every rule here is unit-testable against fixtures.
//!
//! The guiding constraint: **produce exactly the same `InterfaceBase` columns an SNMP poll
//! would.** UniFi is an alternative *source* of LLDP/FDB data, not a parallel topology system,
//! so the server's existing neighbor resolution (`hosts/service/topology.rs`) consumes it
//! unchanged. In particular MACs go through
//! [`LldpChassisId::from_identifier_str`]/[`canonical_mac`], which produce the same canonical
//! lowercase-colon form `from_snmp` does — the raw-string `hosts.chassis_id` fallback compares
//! by string equality, so a UniFi-sourced and an SNMP-sourced chassis ID must be byte-identical.

use std::collections::HashMap;
use std::net::IpAddr;

use uuid::Uuid;

use crate::daemon::discovery::integration::controller::{ControllerIdentity, MappedClient};
use crate::server::interfaces::r#impl::base::{
    IfAdminStatus, IfOperStatus, Interface, InterfaceBase,
};
use crate::server::ip_addresses::r#impl::base::{IPAddress, IPAddressBase};
use crate::server::lldp::{LldpChassisId, LldpPortId, accept_port_identifier, canonical_mac};
use crate::server::subnets::r#impl::base::Subnet;

use super::types::{UnifiDevice, UnifiPort, UnifiStation};

/// IANA ifType 6 — ethernetCsmacd. Every UniFi port we model is a physical Ethernet port.
const IF_TYPE_ETHERNET: i32 = 6;

/// A UniFi device translated into the entities Scanopy stores.
pub struct MappedDevice {
    /// What the controller knows this device by. The caller turns it into a host, or folds it
    /// into the host being scanned — either way the name reaches the ladder the same way.
    pub identity: ControllerIdentity,
    pub ip_address: IPAddress,
    pub interfaces: Vec<Interface>,
    /// The controller's device-class string (`"usw"`, `"uap"`, …), fed to the service matcher
    /// as `ManagedDevice` evidence.
    pub device_type: Option<String>,
    /// Management IP, kept separately because the caller matches it against the scanned IP to
    /// decide which device *is* the controller host.
    pub ip: IpAddr,
}

/// Translate a `stat/device` payload.
///
/// Devices whose IP is missing, unparseable, or outside every known subnet are **skipped**:
/// host deduplication is exclusively IP-based (`hosts/service/mod.rs::select_matching_host`),
/// so a host created without a resolvable IP would mint a fresh duplicate on every scan rather
/// than updating the existing one.
pub fn map_devices(
    devices: &[UnifiDevice],
    network_id: Uuid,
    subnets: &[Subnet],
) -> Vec<MappedDevice> {
    // Index by chassis MAC once, so a downlink can be resolved to the downstream device's own
    // uplink port. Without it a downlink only ever yields a host-level adjacency.
    let by_mac: HashMap<String, &UnifiDevice> = devices
        .iter()
        .filter_map(|d| Some((canonical_mac(d.mac.as_deref()?)?, d)))
        .collect();

    devices
        .iter()
        .filter_map(|device| map_device(device, network_id, subnets, &by_mac))
        .collect()
}

fn map_device(
    device: &UnifiDevice,
    network_id: Uuid,
    subnets: &[Subnet],
    by_mac: &HashMap<String, &UnifiDevice>,
) -> Option<MappedDevice> {
    let ip: IpAddr = device.ip.as_deref()?.trim().parse().ok()?;
    let subnet = subnets.iter().find(|s| s.base.cidr.contains(&ip))?;
    let device_mac = device.mac.as_deref().and_then(canonical_mac);

    let identity = ControllerIdentity {
        name: device.name.clone(),
        // Adopted infrastructure has no separate reported hostname; the controller's name is
        // the only one there is.
        hostname: None,
        // Same canonical form the SNMP daemon writes, so `find_host_by_chassis_id` can reach
        // this device from a neighbor's advertised chassis ID.
        chassis_id: device_mac.clone(),
        manufacturer: Some("Ubiquiti".to_string()),
        model: device.model.clone(),
        serial_number: device.serial.clone(),
        sys_descr: device
            .version
            .as_ref()
            .map(|v| format!("UniFi firmware {v}")),
    };

    let ip_address = IPAddress::new(IPAddressBase {
        network_id,
        host_id: Uuid::nil(), // server assigns
        subnet_id: subnet.id,
        ip_address: ip,
        mac_address: device_mac.as_deref().and_then(|m| m.parse().ok()),
        name: None,
        position: 0,
    });

    Some(MappedDevice {
        identity,
        ip_address,
        interfaces: map_interfaces(device, network_id, device_mac.as_deref(), by_mac),
        device_type: device.device_type.clone().filter(|t| !t.trim().is_empty()),
        ip,
    })
}

/// Build the device's interfaces, then decorate them with neighbor data.
fn map_interfaces(
    device: &UnifiDevice,
    network_id: Uuid,
    device_mac: Option<&str>,
    by_mac: &HashMap<String, &UnifiDevice>,
) -> Vec<Interface> {
    let mut interfaces: Vec<Interface> = device
        .port_table
        .iter()
        .map(|port| port_to_interface(port, network_id, device_mac))
        .collect();

    // A portless device (typically an AP) still has one real interface — its uplink. Model it
    // so the *switch* side of the link can resolve to a specific interface rather than
    // degrading to a host-only neighbor.
    if interfaces.is_empty()
        && let Some(uplink) = &device.uplink
    {
        let if_index = uplink.port_idx.map(|p| p.as_i32()).unwrap_or(1);
        let name = uplink
            .name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| "uplink".to_string());
        interfaces.push(Interface::new(InterfaceBase {
            host_id: Uuid::nil(),
            network_id,
            if_index,
            if_descr: name.clone(),
            if_name: Some(name),
            if_type: IF_TYPE_ETHERNET,
            admin_status: IfAdminStatus::Up,
            oper_status: IfOperStatus::Up,
            // Unlike a switch's repeated port MACs this is the device's own distinct
            // interface address, so it is safe (and useful) to record.
            mac_address: uplink
                .mac
                .as_deref()
                .and_then(canonical_mac)
                .and_then(|m| m.parse().ok()),
            ..Default::default()
        }));
    }

    apply_downlinks(&mut interfaces, device, by_mac);
    apply_uplink(&mut interfaces, device);
    // Last, so it wins: the LLDP table is the highest-fidelity source and the only one that
    // covers non-UniFi neighbors.
    apply_lldp_table(&mut interfaces, device);
    interfaces
}

fn port_to_interface(port: &UnifiPort, network_id: Uuid, device_mac: Option<&str>) -> Interface {
    let if_index = port.port_idx.map(|p| p.as_i32()).unwrap_or(0);
    let name = port
        .name
        .clone()
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        // `if_descr` is validated non-empty, so an unnamed port needs a synthesized label.
        .unwrap_or_else(|| format!("Port {if_index}"));

    let port_mac = port.mac.as_deref().and_then(canonical_mac);
    // UniFi commonly repeats the chassis MAC on every port. Storing it would make the third
    // tier of `InterfaceService::match_existing_interface` (MAC) collapse the entire port
    // table onto a single row — issue #614. Only a genuinely distinct per-port address (as
    // gateways report for WAN/LAN) is recorded.
    let mac_address = port_mac
        .filter(|m| device_mac != Some(m.as_str()))
        .and_then(|m| m.parse().ok());

    let fdb_macs: Vec<String> = port
        .mac_table
        .iter()
        .filter_map(|e| e.mac.as_deref().and_then(canonical_mac))
        .filter(|m| device_mac != Some(m.as_str()))
        .collect();

    Interface::new(InterfaceBase {
        host_id: Uuid::nil(),
        network_id,
        if_index,
        if_descr: name.clone(),
        if_name: Some(name),
        if_type: IF_TYPE_ETHERNET,
        speed_bps: port
            .speed
            .map(|s| s.as_i64() * 1_000_000)
            .filter(|s| *s > 0),
        admin_status: match port.enable.map(|e| e.as_bool()) {
            Some(false) => IfAdminStatus::Down,
            _ => IfAdminStatus::Up,
        },
        oper_status: match port.up.map(|u| u.as_bool()) {
            Some(true) => IfOperStatus::Up,
            _ => IfOperStatus::Down,
        },
        mac_address,
        // `None` rather than an empty vec: the server's unresolved-FDB filter keys on the
        // column being non-NULL.
        fdb_macs: (!fdb_macs.is_empty()).then_some(fdb_macs),
        ..Default::default()
    })
}

/// Record the parent device on the port that faces it.
fn apply_uplink(interfaces: &mut [Interface], device: &UnifiDevice) {
    let Some(uplink) = &device.uplink else { return };
    let Some(parent_mac) = uplink.uplink_mac.as_deref().and_then(canonical_mac) else {
        return;
    };
    let Some(port_idx) = uplink.port_idx.map(|p| p.as_i32()) else {
        return;
    };
    let Some(interface) = interfaces.iter_mut().find(|i| i.base.if_index == port_idx) else {
        return;
    };

    interface.base.lldp_chassis_id = Some(LldpChassisId::MacAddress(parent_mac));
    // `LocallyAssigned` rather than `InterfaceName`: the resolver tries a name lookup *and
    // then* parses the value as an ifIndex, and we set the parent's `if_index` from its own
    // `port_idx`, so the index tier hits. `InterfaceName` would only try the name and
    // dead-end on a bare number.
    interface.base.lldp_port_id = uplink
        .uplink_remote_port
        .map(|p| LldpPortId::LocallyAssigned(p.as_i32().to_string()));
    interface.base.lldp_sys_name = uplink
        .uplink_device_name
        .clone()
        .filter(|n| !n.trim().is_empty());
}

/// Record each adopted child on the port it hangs off.
fn apply_downlinks(
    interfaces: &mut [Interface],
    device: &UnifiDevice,
    by_mac: &HashMap<String, &UnifiDevice>,
) {
    for downlink in &device.downlink_table {
        let Some(child_mac) = downlink.mac.as_deref().and_then(canonical_mac) else {
            continue;
        };
        let Some(port_idx) = downlink.port_idx.map(|p| p.as_i32()) else {
            continue;
        };
        let Some(interface) = interfaces.iter_mut().find(|i| i.base.if_index == port_idx) else {
            continue;
        };

        interface.base.lldp_chassis_id = Some(LldpChassisId::MacAddress(child_mac.clone()));
        // The downlink entry names the child but not which of *its* ports faces us. The child
        // is usually in the same payload and its `uplink.port_idx` is exactly that port, so
        // cross-reference it — otherwise this resolves only to a host, not a `PhysicalLink`.
        interface.base.lldp_port_id = by_mac
            .get(&child_mac)
            .and_then(|child| child.uplink.as_ref())
            .and_then(|u| u.port_idx)
            .map(|p| LldpPortId::LocallyAssigned(p.as_i32().to_string()));
        interface.base.lldp_sys_name = by_mac
            .get(&child_mac)
            .and_then(|child| child.name.clone())
            .filter(|n| !n.trim().is_empty());
    }
}

/// Apply the controller-reported LLDP table, overwriting any uplink/downlink synthesis.
fn apply_lldp_table(interfaces: &mut [Interface], device: &UnifiDevice) {
    for entry in &device.lldp_table {
        let Some(chassis_raw) = entry.chassis_id.as_deref().map(str::trim) else {
            continue;
        };
        if chassis_raw.is_empty() {
            continue;
        }
        let Some(local_idx) = entry.local_port_idx.map(|p| p.as_i32()) else {
            continue;
        };
        let Some(interface) = interfaces.iter_mut().find(|i| i.base.if_index == local_idx) else {
            continue;
        };

        let chassis = LldpChassisId::from_identifier_str(chassis_raw);
        // When the chassis ID is a name rather than a MAC, it is also the best `sysName` we
        // have — and `sys_name` is the resolver's last-resort matching strategy.
        if matches!(chassis, LldpChassisId::LocallyAssigned(_)) {
            interface.base.lldp_sys_name = Some(chassis_raw.to_string());
        }
        interface.base.lldp_chassis_id = Some(chassis);
        // The controller's `port_id` is a free, vendor-formatted string — the neighbour need not
        // be a UniFi device at all — so it gets the same guard as the SNMP, gNMI and lldpd port
        // ids (GH #88). The uplink/downlink synthesis above does not, and does not need it: those
        // ids are rendered from the controller's own integers. `chassis_id` above is left alone
        // deliberately; refusing one is a larger change than #88, see `decode_tlv_name`.
        interface.base.lldp_port_id = entry
            .port_id
            .as_deref()
            .map(str::trim)
            .and_then(|p| accept_port_identifier("unifi", p))
            .filter(|p| !p.is_empty())
            .map(|p| LldpPortId::from_identifier_str(&p));
    }
}

/// Translate a `stat/sta` payload into client hosts.
///
/// `device_ips` are the management addresses of the adopted devices from the same sync. A UDM or
/// switch also appears in the client list, and letting it through would have the client record's
/// DHCP hostname compete with the adopted device's administrator-assigned name at the same rung.
pub fn map_clients(
    stations: &[UnifiStation],
    network_id: Uuid,
    subnets: &[Subnet],
    device_ips: &[IpAddr],
) -> Vec<MappedClient> {
    stations
        .iter()
        .filter_map(|station| {
            let identity = ControllerIdentity {
                name: station.name.clone(),
                hostname: station.hostname.clone(),
                chassis_id: None,
                manufacturer: station.oui.clone(),
                model: None,
                serial_number: None,
                sys_descr: None,
            };
            MappedClient::new(
                identity,
                station.ip.as_deref(),
                station.mac.as_deref(),
                network_id,
                subnets,
            )
        })
        .filter(|client| !device_ips.contains(&client.ip))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::discovery::integration::unifi::types::UnifiEnvelope;
    use crate::server::shared::types::entities::EntitySource;
    use crate::server::subnets::r#impl::base::SubnetBase;
    use crate::server::subnets::r#impl::types::SubnetType;

    // ------------------------------------------------------------------------------------
    // FIXTURE PROVENANCE
    //
    // These payloads are **hand-authored from the unpoller/unifi Go struct definitions and
    // Ubiquiti's documented endpoints — they were NOT captured from a real controller.**
    // Ubiquiti does not publish the `stat/device` sub-table shapes, so the field names and
    // nesting here are our best reading of the de-facto reference, not observed ground truth.
    //
    // They are therefore adequate to pin our *mapping rules* and worthless as evidence that
    // we parse real hardware correctly. When a real `stat/device` capture arrives, drop it in
    // beside these and re-run: shape errors will surface as fields mapping to None.
    // ------------------------------------------------------------------------------------

    const USW_UPLINK: &str = include_str!("../../../../tests/unifi/stat_device_usw_uplink.json");
    const TOPOLOGY: &str = include_str!("../../../../tests/unifi/stat_device_topology.json");
    const FLEX_SCALARS: &str =
        include_str!("../../../../tests/unifi/stat_device_flex_scalars.json");
    const DEGENERATE: &str = include_str!("../../../../tests/unifi/stat_device_degenerate.json");

    fn parse(json: &str) -> Vec<UnifiDevice> {
        let envelope: UnifiEnvelope<UnifiDevice> =
            serde_json::from_str(json).expect("fixture should parse");
        assert!(envelope.meta.is_ok());
        envelope.data
    }

    /// The 192.168.20.0/24 the fixtures live on. `10.99.99.99` is deliberately outside it.
    fn test_subnets(network_id: Uuid) -> Vec<Subnet> {
        vec![Subnet {
            base: SubnetBase {
                name: "Test".to_string(),
                network_id,
                cidr: "192.168.20.0/24".parse().expect("valid CIDR"),
                subnet_type: SubnetType::Lan,
                source: EntitySource::System,
                ..Default::default()
            },
            ..Default::default()
        }]
    }

    fn map(json: &str) -> Vec<MappedDevice> {
        let network_id = Uuid::new_v4();
        map_devices(&parse(json), network_id, &test_subnets(network_id))
    }

    fn interface<'a>(device: &'a MappedDevice, if_index: i32) -> &'a Interface {
        device
            .interfaces
            .iter()
            .find(|i| i.base.if_index == if_index)
            .unwrap_or_else(|| panic!("expected an interface at index {if_index}"))
    }

    fn find<'a>(devices: &'a [MappedDevice], name: &str) -> &'a MappedDevice {
        devices
            .iter()
            .find(|d| d.identity.name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("expected a device named {name}"))
    }

    /// UniFi firmware quotes numbers and booleans inconsistently across versions and device
    /// classes. If a single quoted scalar aborted the parse, the whole topology would be lost.
    #[test]
    fn tolerates_stringified_scalars_and_unknown_keys() {
        let devices = map(FLEX_SCALARS);
        let switch = find(&devices, "Core Switch");
        let port = interface(switch, 5);
        assert_eq!(port.base.speed_bps, Some(1_000_000_000));
        assert_eq!(port.base.oper_status, IfOperStatus::Up);
        assert_eq!(port.base.admin_status, IfAdminStatus::Up);
        // "port_idx": "24" on the uplink still lands the neighbor on port 24.
        assert!(interface(switch, 24).base.lldp_chassis_id.is_some());
    }

    /// `if_descr` is validated non-empty, so an unnamed port must still get a label or the
    /// server rejects the whole interface.
    #[test]
    fn unnamed_ports_get_a_synthesized_description() {
        let devices = map(DEGENERATE);
        let device = devices
            .iter()
            .find(|d| d.ip.to_string() == "192.168.20.50")
            .expect("degenerate switch should be mapped");
        assert_eq!(interface(device, 3).base.if_descr, "Port 3");
        assert!(!interface(device, 8).base.if_descr.is_empty());
    }

    /// UniFi repeats the chassis MAC on every port. Recording it would make the MAC tier of
    /// `match_existing_interface` collapse the whole port table onto one row (issue #614).
    #[test]
    fn chassis_mac_repeated_on_ports_is_not_recorded_but_distinct_macs_are() {
        let devices = map(DEGENERATE);
        let device = devices
            .iter()
            .find(|d| d.ip.to_string() == "192.168.20.50")
            .expect("degenerate switch should be mapped");
        assert_eq!(
            interface(device, 3).base.mac_address,
            None,
            "a port MAC equal to the chassis MAC must not be stored"
        );
        assert!(
            interface(device, 8).base.mac_address.is_some(),
            "a genuinely distinct per-port MAC should be kept"
        );
    }

    /// The single most important assertion here. `resolve_host_id` falls back to raw string
    /// equality against `hosts.chassis_id`, so a UniFi-sourced chassis ID must be byte-identical
    /// to the one an SNMP poll of the same device would produce.
    #[test]
    fn macs_canonicalize_to_the_snmp_form() {
        let devices = map(USW_UPLINK);
        let switch = find(&devices, "Core Switch");
        assert_eq!(
            interface(switch, 24).base.lldp_chassis_id,
            Some(LldpChassisId::MacAddress("00:1a:2b:3c:4d:5e".to_string())),
            "the fixture's mixed-case unpadded '0:1A:2b:3C:4d:5E' must canonicalize"
        );
        assert_eq!(
            switch.identity.chassis_id.as_deref(),
            Some("78:8a:20:11:22:33")
        );
    }

    #[test]
    fn uplink_lands_on_its_own_port_and_resolves_by_index() {
        let devices = map(USW_UPLINK);
        let switch = find(&devices, "Core Switch");
        let uplink_port = interface(switch, 24);
        assert_eq!(
            uplink_port.base.lldp_port_id,
            Some(LldpPortId::LocallyAssigned("4".to_string())),
            "LocallyAssigned resolves by name then ifIndex; InterfaceName would dead-end"
        );
        assert_eq!(
            uplink_port.base.lldp_sys_name.as_deref(),
            Some("Border Gateway")
        );
        // No other port picked up the parent.
        assert_eq!(
            switch
                .interfaces
                .iter()
                .filter(|i| i.base.lldp_chassis_id.is_some())
                .count(),
            2, // port 24 (uplink) and port 12 (lldp_table neighbor)
        );
    }

    /// A downlink names the child but not which of the child's ports faces us. Cross-referencing
    /// the child's own uplink is what upgrades the link from a host adjacency to a PhysicalLink.
    #[test]
    fn downlink_resolves_the_far_port_via_the_childs_uplink() {
        let devices = map(TOPOLOGY);
        let gateway = find(&devices, "Border Gateway");
        let port = interface(gateway, 4);
        assert_eq!(
            port.base.lldp_chassis_id,
            Some(LldpChassisId::MacAddress("78:8a:20:11:22:33".to_string()))
        );
        assert_eq!(
            port.base.lldp_port_id,
            Some(LldpPortId::LocallyAssigned("24".to_string())),
            "the switch's own uplink.port_idx is the far end of this link"
        );
    }

    /// Degrades to a host-level neighbor rather than inventing a port when the peer is absent.
    #[test]
    fn downlink_without_the_peer_in_the_payload_has_no_far_port() {
        let network_id = Uuid::new_v4();
        let mut devices = parse(TOPOLOGY);
        devices.retain(|d| d.name.as_deref() != Some("Core Switch"));
        let mapped = map_devices(&devices, network_id, &test_subnets(network_id));

        let gateway = find(&mapped, "Border Gateway");
        let port = interface(gateway, 4);
        assert!(
            port.base.lldp_chassis_id.is_some(),
            "we still know which device is down there"
        );
        assert_eq!(
            port.base.lldp_port_id, None,
            "but not which of its ports, so claim nothing"
        );
    }

    /// The LLDP table is the only source covering non-UniFi neighbors — the customer's actual
    /// case — so it must win over uplink/downlink synthesis on the same port.
    #[test]
    fn lldp_table_covers_non_unifi_neighbors_and_names_unrecognized_chassis_ids() {
        let devices = map(DEGENERATE);
        let device = devices
            .iter()
            .find(|d| d.ip.to_string() == "192.168.20.50")
            .expect("degenerate switch should be mapped");
        let port = interface(device, 8);
        assert_eq!(
            port.base.lldp_chassis_id,
            Some(LldpChassisId::LocallyAssigned(
                "legacy-switch.lan".to_string()
            )),
            "a hostname-shaped chassis ID must not be coerced into a MAC"
        );
        assert_eq!(
            port.base.lldp_sys_name.as_deref(),
            Some("legacy-switch.lan"),
            "it is also the best sysName we have, which is the resolver's last resort"
        );
        assert_eq!(
            port.base.lldp_port_id,
            Some(LldpPortId::LocallyAssigned("1/1/8".to_string()))
        );
    }

    /// GH #88 on the fourth boundary. The controller's `port_id` is documented as "the
    /// neighbour's port identifier, vendor-formatted" — a free string from a device that need not
    /// be UniFi at all — so it is the same class of value as the SNMP payload that started #88,
    /// and it reached `from_identifier_str` unguarded.
    ///
    /// The same case also pins the two things that must *not* change: `chassis_id` is still
    /// recorded whatever it holds (refusing one drops the row out of L2 resolution entirely,
    /// which is a separate change), and GH #668's NUL-terminated port id still yields its name.
    #[test]
    fn a_controller_port_id_that_is_not_a_name_is_refused() {
        use crate::daemon::discovery::integration::unifi::types::{FlexInt, UnifiLldpEntry};

        let apply = |port_id: &str| {
            let mut interfaces = vec![Interface {
                base: InterfaceBase {
                    if_index: 8,
                    ..Default::default()
                },
                ..Default::default()
            }];
            let device = UnifiDevice {
                lldp_table: vec![UnifiLldpEntry {
                    chassis_id: Some("legacy-switch.lan".to_string()),
                    port_id: Some(port_id.to_string()),
                    local_port_idx: Some(FlexInt(8)),
                    ..Default::default()
                }],
                ..Default::default()
            };
            apply_lldp_table(&mut interfaces, &device);
            interfaces.remove(0).base
        };

        let refused = apply("1/1/\u{1}8");
        assert_eq!(refused.lldp_port_id, None);
        assert_eq!(
            refused.lldp_chassis_id,
            Some(LldpChassisId::LocallyAssigned("legacy-switch.lan".into())),
            "the chassis id is deliberately still recorded; only the port id is guarded"
        );

        let padded = apply("1\0");
        assert_eq!(
            padded.lldp_port_id,
            Some(LldpPortId::LocallyAssigned("1".into())),
            "GH #668's NUL padding is stripped here as on every other boundary"
        );

        let good = apply("1/1/8");
        assert_eq!(
            good.lldp_port_id,
            Some(LldpPortId::LocallyAssigned("1/1/8".into()))
        );
    }

    /// The server's unresolved-FDB filter keys on the column being non-NULL, so an empty
    /// table must be `None` rather than `Some(vec![])`.
    #[test]
    fn fdb_omits_the_devices_own_mac_and_stays_none_when_empty() {
        let devices = map(USW_UPLINK);
        let switch = find(&devices, "Core Switch");
        assert_eq!(
            interface(switch, 1).base.fdb_macs,
            Some(vec!["aa:bb:cc:00:00:01".to_string()])
        );
        assert_eq!(
            interface(switch, 2).base.fdb_macs.as_ref().map(Vec::len),
            Some(2)
        );
        assert_eq!(interface(switch, 3).base.fdb_macs, None);

        let degenerate = map(DEGENERATE);
        let device = degenerate
            .iter()
            .find(|d| d.ip.to_string() == "192.168.20.50")
            .expect("degenerate switch should be mapped");
        assert_eq!(
            interface(device, 8).base.fdb_macs,
            None,
            "a table containing only the device's own MAC contributes nothing"
        );
    }

    /// A device with no IP, or an IP outside every known subnet, cannot be deduplicated by the
    /// server (host identity is IP-based) and would mint a duplicate host on every scan.
    #[test]
    fn devices_without_a_placeable_ip_are_skipped() {
        let devices = map(DEGENERATE);
        assert_eq!(
            devices.len(),
            1,
            "only the 192.168.20.50 device is placeable"
        );
        assert!(devices.iter().all(|d| d.ip.to_string() == "192.168.20.50"));
    }

    /// An AP has no port table, but it does have one real interface. Modelling it lets the
    /// switch side resolve to a specific interface instead of a host-only partial.
    #[test]
    fn portless_devices_get_one_interface_from_their_uplink() {
        let devices = map(TOPOLOGY);
        let ap = find(&devices, "Office AP");
        assert_eq!(ap.interfaces.len(), 1);
        let uplink = &ap.interfaces[0];
        assert_eq!(uplink.base.if_index, 1);
        assert_eq!(
            uplink
                .base
                .mac_address
                .map(|m| m.to_string().to_lowercase()),
            Some("f0:9f:c2:aa:00:12".to_string()),
            "an AP's eth0 MAC is genuinely distinct, unlike a switch's repeated port MACs"
        );
        assert_eq!(
            uplink.base.lldp_chassis_id,
            Some(LldpChassisId::MacAddress("78:8a:20:11:22:33".to_string()))
        );
    }

    /// End-to-end shape check over a three-device payload.
    #[test]
    fn maps_a_full_topology_payload() {
        let devices = map(TOPOLOGY);
        assert_eq!(devices.len(), 3);
        assert_eq!(
            find(&devices, "Border Gateway").device_type.as_deref(),
            Some("udm")
        );
        assert_eq!(
            find(&devices, "Core Switch").device_type.as_deref(),
            Some("usw")
        );
        assert_eq!(
            find(&devices, "Office AP").device_type.as_deref(),
            Some("uap")
        );
        for device in &devices {
            assert_eq!(device.identity.manufacturer.as_deref(), Some("Ubiquiti"));
            assert!(device.identity.chassis_id.is_some());
        }
    }
}
