use super::*;
use crate::server::interfaces::r#impl::base::{IfAdminStatus, IfOperStatus, if_type};
use crate::server::lldp::LldpPortId;
use crate::server::snmp::generated::get_if_type_number;
use proto::gnmi::{Notification, TypedValue, Update, typed_value};

/// A device answering Subscribe ONCE per subtree from scripts of `path = value` lines, the
/// way ArcOS does: one typed leaf per update, no prefix. A subtree with no script is
/// refused with the `InvalidArgument` a real device sends. Paths are gnmic-style
/// (`lldp/interfaces/interface[name=swp1]/neighbors/neighbor[id=1]/state/port-id`).
#[derive(Default)]
struct ScriptedDevice {
    served: BTreeMap<&'static str, &'static str>,
    /// Subtrees whose Subscribe fails with this error rather than a refusal.
    failures: BTreeMap<&'static str, &'static str>,
}

impl ScriptedDevice {
    fn serve(mut self, subtree: Subtree, script: &'static str) -> Self {
        self.served.insert(subtree_key(subtree), script);
        self
    }

    fn fail(mut self, subtree: Subtree, error: &'static str) -> Self {
        self.failures.insert(subtree_key(subtree), error);
        self
    }
}

fn subtree_key(subtree: Subtree) -> &'static str {
    match subtree {
        Subtree::InterfaceState => "interfaces/interface[name=*]/state",
        Subtree::EthernetState => "interfaces/interface[name=*]/ethernet/state",
        Subtree::LldpLocal => "lldp/state",
        Subtree::LldpNeighbors => "lldp/interfaces/interface[name=*]",
    }
}

fn render_path(path: &Path) -> String {
    path.elem
        .iter()
        .map(|e| {
            let keys: String = e.key.iter().map(|(k, v)| format!("[{k}={v}]")).collect();
            format!("{}{keys}", e.name)
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Split on `/` outside brackets only: key values carry slashes (`[name=ge10-0/0/0]`).
fn split_elems(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut depth) = (0, 0);
    for (i, c) in path.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            '/' if depth == 0 => {
                out.push(&path[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&path[start..]);
    out.into_iter().filter(|e| !e.is_empty()).collect()
}

fn parse_path(path: &str) -> Path {
    Path {
        elem: split_elems(path)
            .into_iter()
            .map(|e| match e.split_once('[') {
                Some((name, key)) => {
                    let (k, v) = key.trim_end_matches(']').split_once('=').unwrap();
                    PathElem {
                        name: name.into(),
                        key: [(k.to_string(), v.to_string())].into_iter().collect(),
                    }
                }
                None => PathElem {
                    name: e.into(),
                    ..Default::default()
                },
            })
            .collect(),
        ..Default::default()
    }
}

fn typed(value: &str) -> TypedValue {
    // Numbers travel as uint leaves on the wire (ifindex, mtu); everything else is text.
    let v = match value.parse::<u64>() {
        Ok(u) => typed_value::Value::UintVal(u),
        Err(_) => typed_value::Value::StringVal(value.to_string()),
    };
    TypedValue { value: Some(v) }
}

/// One notification per non-blank script line, `path = value`.
fn script_to_notifications(script: &str) -> Vec<Notification> {
    script
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|line| {
            let (path, value) = line.split_once(" = ").unwrap_or((line, ""));
            Notification {
                update: vec![Update {
                    path: Some(parse_path(path.trim())),
                    val: Some(typed(value.trim())),
                    ..Default::default()
                }],
                ..Default::default()
            }
        })
        .collect()
}

#[async_trait]
impl GnmiTransport for ScriptedDevice {
    async fn capabilities(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn subscribe_once(&mut self, paths: Vec<Path>) -> anyhow::Result<Vec<Notification>> {
        let [path] = paths.as_slice() else {
            panic!("the collector subscribes one subtree at a time");
        };
        let key = render_path(path);
        if let Some(error) = self.failures.get(key.as_str()) {
            anyhow::bail!("{error}");
        }
        match self.served.get(key.as_str()) {
            Some(script) => Ok(script_to_notifications(script)),
            None => anyhow::bail!(
                "gNMI Subscribe failed: code: 'Client specified an invalid argument', \
                 message: \"Requested Path '{key}' is not supported\""
            ),
        }
    }
}

// Captured 2026-08-25 from netlab-leaf1 (Arrcus ArcOS 8.5, Edgecore AS7326-56X), Subscribe
// ONCE, PROTO encoding, via this crate's own transport (gnmic was not to hand). Trimmed to
// a handful of the 60 rows; the leaves kept are verbatim, counters included where they
// show what is ignored. ArcOS sends `type` without the `iana-if-type:` prefix, blank
// `description` leaves for undescribed ports, and no `mac-address` anywhere.
const ARCOS_INTERFACE_STATE: &str = "
    interfaces/interface[name=swp1]/state/counters/out-octets = 2487600
    interfaces/interface[name=swp1]/state/type = ethernetCsmacd
    interfaces/interface[name=swp1]/state/ifindex = 1001
    interfaces/interface[name=swp1]/state/oper-status = UP
    interfaces/interface[name=swp1]/state/admin-status = UP
    interfaces/interface[name=swp1]/state/description =
    interfaces/interface[name=swp1]/state/mtu = 1526
    interfaces/interface[name=swp1]/state/name = swp1
    interfaces/interface[name=swp46]/state/admin-status = UP
    interfaces/interface[name=swp46]/state/description = netlab-mgmt0 : Ethernet48
    interfaces/interface[name=swp46]/state/ifindex = 1046
    interfaces/interface[name=swp46]/state/oper-status = UP
    interfaces/interface[name=swp46]/state/type = ethernetCsmacd
    interfaces/interface[name=swp53]/state/admin-status = UP
    interfaces/interface[name=swp53]/state/description =
    interfaces/interface[name=swp53]/state/ifindex = 1053
    interfaces/interface[name=swp53]/state/oper-status = UP
    interfaces/interface[name=swp53]/state/type = ethernetCsmacd
    interfaces/interface[name=swp55]/state/admin-status = UP
    interfaces/interface[name=swp55]/state/description = PROTECT: netlab-spine2 : swp32 : FOR UNDERLAY
    interfaces/interface[name=swp55]/state/ifindex = 1055
    interfaces/interface[name=swp55]/state/oper-status = UP
    interfaces/interface[name=swp55]/state/type = ethernetCsmacd
    interfaces/interface[name=loopback0]/state/admin-status = UP
    interfaces/interface[name=loopback0]/state/ifindex = 20005
    interfaces/interface[name=loopback0]/state/oper-status = UP
    interfaces/interface[name=loopback0]/state/type = softwareLoopback
    interfaces/interface[name=vlan1000]/state/admin-status = UP
    interfaces/interface[name=vlan1000]/state/type = l3ipvlan
    interfaces/interface[name=vlan1000]/state/ifindex = 20031
    interfaces/interface[name=vlan1000]/state/oper-status = UP
    interfaces/interface[name=ma1]/state/ifindex = 4
    interfaces/interface[name=ma1]/state/type = ethernetCsmacd
    interfaces/interface[name=ma1]/state/admin-status = UP
    interfaces/interface[name=ma1]/state/oper-status = UP
";

/// ArcOS's `ethernet/state` carries only its own `effective-speed` (Mb/s), not the model's
/// `port-speed` identity, so it contributes nothing to the row.
const ARCOS_ETHERNET_STATE: &str = "
    interfaces/interface[name=swp1]/ethernet/state/effective-speed = 25000
    interfaces/interface[name=swp53]/ethernet/state/effective-speed = 100000
    interfaces/interface[name=ma1]/ethernet/state/effective-speed = 1000
";

/// No `chassis-id` leaf on any neighbour. A Linux lldpd peer (netlab-server) shows up
/// twice on swp1 and swp53, one entry per chassis-id subtype it advertises; only one
/// carries the management address and system name.
const ARCOS_LLDP_NEIGHBORS: &str = "
    lldp/interfaces/interface[name=swp1]/name = swp1
    lldp/interfaces/interface[name=swp1]/neighbors/neighbor[id=5-34:80:0d:44:45:05]/id = 5-34:80:0d:44:45:05
    lldp/interfaces/interface[name=swp1]/neighbors/neighbor[id=5-34:80:0d:44:45:05]/state/id = 5-34:80:0d:44:45:05
    lldp/interfaces/interface[name=swp1]/neighbors/neighbor[id=5-34:80:0d:44:45:05]/state/port-id = 34:80:0d:44:45:05
    lldp/interfaces/interface[name=swp1]/neighbors/neighbor[id=7-34:80:0d:44:44:f5]/id = 7-34:80:0d:44:44:f5
    lldp/interfaces/interface[name=swp1]/neighbors/neighbor[id=7-34:80:0d:44:44:f5]/state/id = 7-34:80:0d:44:44:f5
    lldp/interfaces/interface[name=swp1]/neighbors/neighbor[id=7-34:80:0d:44:44:f5]/state/management-address = 10.22.64.101
    lldp/interfaces/interface[name=swp1]/neighbors/neighbor[id=7-34:80:0d:44:44:f5]/state/port-id = 34:80:0d:44:44:f5
    lldp/interfaces/interface[name=swp1]/neighbors/neighbor[id=7-34:80:0d:44:44:f5]/state/system-description = Ubuntu 26.04 LTS Linux 7.0.0-30-generic #30-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul 31 18:22:54 UTC 2026 x86_64
    lldp/interfaces/interface[name=swp1]/neighbors/neighbor[id=7-34:80:0d:44:44:f5]/state/system-name = netlab-server
    lldp/interfaces/interface[name=swp46]/name = swp46
    lldp/interfaces/interface[name=swp46]/neighbors/neighbor[id=1-Ethernet48]/state/management-address = fe80::deda:4dff:fe86:f4ea
    lldp/interfaces/interface[name=swp46]/neighbors/neighbor[id=1-Ethernet48]/state/port-id = Ethernet48
    lldp/interfaces/interface[name=swp46]/neighbors/neighbor[id=1-Ethernet48]/state/system-description = SONiC Software Version: SONiC-OS-cls_sonic_plus_4.0.0-de0fd7e72 - HwSku: Celestica ES1010-48CP - Distribution: Debian 11.11 - Kernel: 5.10.0-32-2-amd64
    lldp/interfaces/interface[name=swp46]/neighbors/neighbor[id=1-Ethernet48]/state/system-name = netlab-mgmt0
    lldp/interfaces/interface[name=swp53]/neighbors/neighbor[id=6-98:03:9b:7f:6f:58]/state/port-id = 98:03:9b:7f:6f:58
    lldp/interfaces/interface[name=swp53]/neighbors/neighbor[id=7-98:03:9b:7f:6f:58]/state/management-address = 10.22.64.101
    lldp/interfaces/interface[name=swp53]/neighbors/neighbor[id=7-98:03:9b:7f:6f:58]/state/port-id = 98:03:9b:7f:6f:58
    lldp/interfaces/interface[name=swp53]/neighbors/neighbor[id=7-98:03:9b:7f:6f:58]/state/system-name = netlab-server
    lldp/interfaces/interface[name=swp55]/neighbors/neighbor[id=3-swp32]/state/management-address = 10.22.64.103
    lldp/interfaces/interface[name=swp55]/neighbors/neighbor[id=3-swp32]/state/port-id = swp32
    lldp/interfaces/interface[name=swp55]/neighbors/neighbor[id=3-swp32]/state/system-description = Arrcus Operating System (ArcOS)
    lldp/interfaces/interface[name=swp55]/neighbors/neighbor[id=3-swp32]/state/system-name = netlab-spine2
";

fn arcos() -> ScriptedDevice {
    // `/lldp/state` is what leaf1 refuses: "Requested Path 'lldp/state' is not supported".
    ScriptedDevice::default()
        .serve(Subtree::InterfaceState, ARCOS_INTERFACE_STATE)
        .serve(Subtree::EthernetState, ARCOS_ETHERNET_STATE)
        .serve(Subtree::LldpNeighbors, ARCOS_LLDP_NEIGHBORS)
}

async fn rows(device: &mut ScriptedDevice) -> (Collection, Vec<Interface>) {
    let coll = collect(device).await.expect("collection succeeds");
    let rows = collection_to_interfaces(&coll, uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    (coll, rows)
}

fn row<'a>(rows: &'a [Interface], name: &str) -> &'a InterfaceBase {
    &rows
        .iter()
        .find(|i| i.base.if_name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("no row for {name}"))
        .base
}

/// The one LLDP neighbour a row carries.
fn lldp(base: &InterfaceBase) -> &InterfaceNeighborEvidence {
    base.neighbor_candidates
        .first()
        .unwrap_or_else(|| panic!("no neighbour on {:?}", base.if_name))
}

/// The whole ArcOS shape: rows from `/interfaces` with real ifIndexes and types, the LLDP
/// neighbour joined on name, `/lldp/state` refused without consequence.
#[tokio::test]
async fn arcos_rows_join_interfaces_and_lldp() {
    let (coll, rows) = rows(&mut arcos()).await;
    assert!(
        coll.data_complete().lldp,
        "/lldp answered: its neighbour set is authoritative"
    );
    assert_eq!(
        rows.len(),
        7,
        "one row per /interfaces entry, LLDP adds none"
    );

    let swp1 = row(&rows, "swp1");
    assert_eq!(swp1.if_index, Some(1001));
    assert_eq!(swp1.if_descr.as_deref(), Some("swp1"));
    assert_eq!(swp1.if_alias, None, "a blank description leaf is no alias");
    assert_eq!(swp1.if_type, Some(6), "ethernetCsmacd");
    assert_eq!(swp1.admin_status, Some(IfAdminStatus::Up));
    assert_eq!(swp1.oper_status, Some(IfOperStatus::Up));
    assert_eq!(swp1.mac_address, None, "ArcOS serves no mac-address leaf");
    assert_eq!(
        swp1.speed_bps, None,
        "effective-speed is not the model's port-speed"
    );
    // Two entries for the same peer, both kept. Neither carries a chassis-id leaf: the thin
    // one is identified by its MAC-shaped port-id, the other by its management address.
    let [thin, rich] = swp1.neighbor_candidates.as_slice() else {
        panic!(
            "every neighbour on the port, got {:?}",
            swp1.neighbor_candidates
        );
    };
    assert_eq!(
        thin.lldp_chassis_id,
        Some(LldpChassisId::MacAddress("34:80:0d:44:45:05".into())),
        "no chassis-id leaf and no address: the MAC-shaped port-id is the identity"
    );
    assert_eq!(thin.lldp_sys_name, None);
    assert_eq!(thin.lldp_mgmt_addr, None);
    assert_eq!(rich.lldp_sys_name.as_deref(), Some("netlab-server"));
    assert_eq!(
        rich.lldp_chassis_id,
        Some(LldpChassisId::NetworkAddress(
            "10.22.64.101".parse().unwrap()
        )),
        "no chassis-id leaf: the management address is the identity"
    );
    assert_eq!(
        rich.lldp_port_id,
        Some(LldpPortId::MacAddress("34:80:0d:44:44:f5".into()))
    );
    assert_eq!(
        row(&rows, "swp53").neighbor_candidates.len(),
        2,
        "the same double listing on swp53"
    );

    assert_eq!(
        row(&rows, "swp46").if_alias.as_deref(),
        Some("netlab-mgmt0 : Ethernet48")
    );
    assert_eq!(
        row(&rows, "loopback0").if_type,
        Some(24),
        "softwareLoopback"
    );
    // IANA 136, the number SNMP's ifType reports for the same SVI. Not `if_type::L3_IPVLAN`,
    // which is 137 (IANA's l3ipxvlan).
    assert_eq!(row(&rows, "vlan1000").if_type, Some(136), "l3ipvlan");
    assert_eq!(row(&rows, "ma1").if_index, Some(4));

    let swp55 = lldp(row(&rows, "swp55"));
    assert_eq!(swp55.lldp_sys_name.as_deref(), Some("netlab-spine2"));
    assert_eq!(swp55.lldp_mgmt_addr, Some("10.22.64.103".parse().unwrap()));
    assert_eq!(
        swp55.lldp_sys_desc.as_deref(),
        Some("Arrcus Operating System (ArcOS)")
    );
    // A link-local management address still parses; whether it resolves is the server's
    // business.
    assert_eq!(
        lldp(row(&rows, "swp46")).lldp_mgmt_addr,
        Some("fe80::deda:4dff:fe86:f4ea".parse().unwrap())
    );
}

/// A device whose LLDP read fails, refused or timed out, still yields its rows but not an
/// authoritative neighbour set, so the server keeps the neighbours it holds instead of
/// clearing them on one bad read.
#[tokio::test]
async fn failed_lldp_read_keeps_rows_and_is_not_authoritative() {
    let refused = ScriptedDevice::default()
        .serve(Subtree::InterfaceState, ARCOS_INTERFACE_STATE)
        .serve(Subtree::EthernetState, ARCOS_ETHERNET_STATE);
    let timed_out = ScriptedDevice::default()
        .serve(Subtree::InterfaceState, ARCOS_INTERFACE_STATE)
        .serve(Subtree::EthernetState, ARCOS_ETHERNET_STATE)
        .fail(Subtree::LldpNeighbors, "gNMI Subscribe stream timed out");
    for (case, mut device) in [("refused", refused), ("timed out", timed_out)] {
        let (coll, rows) = rows(&mut device).await;
        assert!(
            !coll.data_complete().lldp,
            "{case}: lldp must not be authoritative"
        );
        assert_eq!(
            rows.len(),
            7,
            "{case}: interface rows come through without LLDP"
        );
        assert!(
            rows.iter().all(|r| r.base.neighbor_candidates.is_empty()),
            "{case}"
        );
    }
}

/// An update whose JSON blob does not parse is reported, so a garbled LLDP subtree counts as
/// a failed read rather than an empty one.
#[test]
fn unparseable_json_update_is_reported() {
    let n = Notification {
        update: vec![Update {
            path: Some(parse_path("lldp")),
            val: Some(TypedValue {
                value: Some(typed_value::Value::JsonIetfVal(b"{not json".to_vec())),
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(!absorb_notification(&mut Collection::default(), &n));
}

/// A device serving LLDP but not `openconfig-interfaces` is an error naming the refused
/// path, not a set of rows invented from neighbour names: such rows (no ifIndex, no
/// statuses) would shadow a real ifTable when SNMP runs against the same device.
#[tokio::test]
async fn interfaces_refused_is_an_error_even_with_lldp_present() {
    let mut device = ScriptedDevice::default().serve(Subtree::LldpNeighbors, ARCOS_LLDP_NEIGHBORS);
    let err = collect(&mut device).await.expect_err("no /interfaces");
    let msg = format!("{err:#}");
    assert!(msg.contains("openconfig-interfaces is required"), "{msg}");
    assert!(
        msg.contains("'interfaces/interface[name=*]/state' is not supported"),
        "{msg}"
    );
}

/// A JSON_IETF blob — hand-built to the openconfig-interfaces model, since no device in
/// the lab answers with one — flattens to the same leaves, module prefixes and all, list
/// entries keyed by their `name`. Subinterfaces carry their own `ifindex` and are skipped.
#[test]
fn json_ietf_blob_flattens_to_the_same_leaves() {
    let blob = serde_json::json!({
        "openconfig-interfaces:interface": [{
            "name": "Ethernet1",
            "state": {
                "ifindex": 1,
                "type": "iana-if-type:ethernetCsmacd",
                "admin-status": "UP",
                "oper-status": "LOWER_LAYER_DOWN",
                "description": "uplink"
            },
            "openconfig-if-ethernet:ethernet": {
                "state": {
                    "mac-address": "c0:c9:89:ef:20:d2",
                    "port-speed": "openconfig-if-ethernet:SPEED_10GB"
                }
            },
            "subinterfaces": {
                "subinterface": [{ "index": 0, "state": { "ifindex": 5 } }]
            }
        }]
    });
    let n = Notification {
        update: vec![Update {
            path: Some(parse_path("interfaces")),
            val: Some(TypedValue {
                value: Some(typed_value::Value::JsonIetfVal(
                    blob.to_string().into_bytes(),
                )),
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut coll = Collection::default();
    absorb_notification(&mut coll, &n);
    let rows = collection_to_interfaces(&coll, uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let eth1 = row(&rows, "Ethernet1");
    assert_eq!(
        eth1.if_index,
        Some(1),
        "the interface's ifindex, not the subinterface's"
    );
    assert_eq!(eth1.if_alias.as_deref(), Some("uplink"));
    assert_eq!(eth1.oper_status, Some(IfOperStatus::LowerLayerDown));
    assert_eq!(
        crate::server::ip_addresses::r#impl::base::mac_of(&eth1.mac_address)
            .map(|m| m.to_string().to_lowercase()),
        Some("c0:c9:89:ef:20:d2".into())
    );
    assert_eq!(eth1.speed_bps, Some(10_000_000_000));
}

/// A device that DOES serve chassis-id/-type maps faithfully, notification prefix and
/// `/lldp/state` included.
#[test]
fn explicit_chassis_type_maps_and_prefix_is_honoured() {
    let n = Notification {
        prefix: Some(parse_path("lldp")),
        update: [
            (
                "interfaces/interface[name=eth0]/neighbors/neighbor[id=1]/state/chassis-id",
                "C0:C9:89:EF:20:D2",
            ),
            (
                "interfaces/interface[name=eth0]/neighbors/neighbor[id=1]/state/chassis-id-type",
                "openconfig-lldp-types:MAC_ADDRESS",
            ),
            (
                "interfaces/interface[name=eth0]/neighbors/neighbor[id=1]/state/port-id",
                "Gi1/0/1",
            ),
            (
                "interfaces/interface[name=eth0]/neighbors/neighbor[id=1]/state/port-id-type",
                "openconfig-lldp-types:INTERFACE_NAME",
            ),
            ("state/chassis-id", "00:11:22:33:44:55"),
            ("state/chassis-id-type", "openconfig-lldp-types:MAC_ADDRESS"),
        ]
        .into_iter()
        .map(|(p, v)| Update {
            path: Some(parse_path(p)),
            val: Some(typed(v)),
            ..Default::default()
        })
        .collect(),
        ..Default::default()
    };
    let mut coll = Collection::default();
    absorb_notification(&mut coll, &n);
    // The row itself comes from `/interfaces`; the neighbour only decorates it.
    absorb_notification(
        &mut coll,
        &Notification {
            update: vec![Update {
                path: Some(parse_path("interfaces/interface[name=eth0]/state/ifindex")),
                val: Some(typed("3")),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    assert_eq!(coll.local_chassis_id.as_deref(), Some("00:11:22:33:44:55"));
    let rows = collection_to_interfaces(&coll, uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let eth0 = row(&rows, "eth0");
    assert_eq!(eth0.if_index, Some(3));
    assert_eq!(
        lldp(eth0).lldp_chassis_id,
        Some(LldpChassisId::MacAddress("c0:c9:89:ef:20:d2".into()))
    );
    assert_eq!(
        lldp(eth0).lldp_port_id,
        Some(LldpPortId::InterfaceName("Gi1/0/1".into()))
    );
}

/// The generated reverse map itself, independent of identity handling.
#[test]
fn generated_reverse_map_matches_the_registry() {
    assert_eq!(get_if_type_number("ethernetCsmacd"), Some(6));
    assert_eq!(get_if_type_number("l2vlan"), Some(135));
    assert_eq!(get_if_type_number("notAnIfType"), None);
}

#[test]
fn identities_map_by_iana_name_whatever_the_prefix() {
    assert_eq!(if_type_from_identity("ethernetCsmacd"), 6);
    assert_eq!(if_type_from_identity("iana-if-type:ieee8023adLag"), 161);
    assert_eq!(if_type_from_identity("ianaift:propVirtual"), 53);
    assert_eq!(if_type_from_identity("iana-if-type:l2vlan"), 135);
    assert_eq!(if_type_from_identity("iana-if-type:l3ipvlan"), 136);
    // Registered, just not one the constants name: the table covers it.
    assert_eq!(if_type_from_identity("iana-if-type:atm"), 37);
    assert_eq!(
        if_type_from_identity("iana-if-type:noSuchType"),
        if_type::OTHER
    );
    assert_eq!(speed_from_identity("SPEED_100MB"), Some(100_000_000));
    assert_eq!(
        speed_from_identity("openconfig-if-ethernet:SPEED_2500MB"),
        Some(2_500_000_000)
    );
    assert_eq!(speed_from_identity("SPEED_400GB"), Some(400_000_000_000));
    assert_eq!(speed_from_identity("SPEED_UNKNOWN"), None);
}

// Captured 2026-08-25 from a DriveNets DNOS 72XC with gnmic 0.47 (`subscribe --mode once
// --encoding proto`, port 50051). DNOS serves `/interfaces` the same per-leaf way and
// refuses every `/lldp` path ("No valid requests in the session"); its `type` leaves mix
// IANA names with vendor ones (`irb`, `mgmt-ncx-member`).
const DNOS_INTERFACE_STATE: &str = "
    interfaces/interface[name=ge10-0/0/0]/state/admin-status = UP
    interfaces/interface[name=ge10-0/0/0]/state/ifindex = 1
    interfaces/interface[name=ge10-0/0/0]/state/mtu = 1514
    interfaces/interface[name=ge10-0/0/0]/state/name = ge10-0/0/0
    interfaces/interface[name=ge10-0/0/0]/state/oper-status = DOWN
    interfaces/interface[name=ge10-0/0/0]/state/type = ethernetCsmacd
    interfaces/interface[name=bundle-10]/state/admin-status = UP
    interfaces/interface[name=bundle-10]/state/ifindex = 12289
    interfaces/interface[name=bundle-10]/state/oper-status = DOWN
    interfaces/interface[name=bundle-10]/state/type = ieee8023adLag
    interfaces/interface[name=bundle-10.4090]/state/admin-status = UP
    interfaces/interface[name=bundle-10.4090]/state/ifindex = 13313
    interfaces/interface[name=bundle-10.4090]/state/oper-status = DOWN
    interfaces/interface[name=bundle-10.4090]/state/type = l2vlan
    interfaces/interface[name=irb100]/state/admin-status = UP
    interfaces/interface[name=irb100]/state/ifindex = 41985
    interfaces/interface[name=irb100]/state/oper-status = DOWN
    interfaces/interface[name=irb100]/state/type = irb
    interfaces/interface[name=lo0]/state/admin-status = UP
    interfaces/interface[name=lo0]/state/description = loopback
    interfaces/interface[name=lo0]/state/ifindex = 8193
    interfaces/interface[name=lo0]/state/oper-status = UP
    interfaces/interface[name=lo0]/state/type = softwareLoopback
    interfaces/interface[name=mgmt-ncc-0/0]/state/admin-status = UP
    interfaces/interface[name=mgmt-ncc-0/0]/state/ifindex = 46333
    interfaces/interface[name=mgmt-ncc-0/0]/state/oper-status = UP
    interfaces/interface[name=mgmt-ncc-0/0]/state/type = mgmt-ncx-member
";

/// A device with `openconfig-interfaces` and no LLDP model at all still yields an
/// authoritative interface set, neighbourless; vendor-private types land as `other`. Its
/// neighbour set is not authoritative: `/lldp` refused as unsupported is SNMP's
/// `unsupported`, which never clears.
#[tokio::test]
async fn dnos_interfaces_without_any_lldp_model() {
    let mut device = ScriptedDevice::default().serve(Subtree::InterfaceState, DNOS_INTERFACE_STATE);
    let (coll, rows) = rows(&mut device).await;
    assert!(!coll.data_complete().lldp);
    assert_eq!(rows.len(), 6);
    assert!(rows.iter().all(|r| r.base.neighbor_candidates.is_empty()));
    let ge = row(&rows, "ge10-0/0/0");
    assert_eq!(ge.if_index, Some(1));
    assert_eq!(ge.oper_status, Some(IfOperStatus::Down));
    assert_eq!(row(&rows, "bundle-10").if_type, Some(161), "ieee8023adLag");
    assert_eq!(row(&rows, "bundle-10.4090").if_type, Some(135), "l2vlan");
    assert_eq!(row(&rows, "irb100").if_type, Some(if_type::OTHER));
    assert_eq!(row(&rows, "mgmt-ncc-0/0").if_type, Some(if_type::OTHER));
    assert_eq!(row(&rows, "lo0").if_alias.as_deref(), Some("loopback"));
}
