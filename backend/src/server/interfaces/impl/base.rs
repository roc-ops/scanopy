use crate::server::lldp::{LldpChassisId, LldpPortId};
use crate::server::shared::entities::ChangeTriggersTopologyStaleness;
use crate::server::shared::types::{
    Color, Icon,
    metadata::{EntityMetadataProvider, HasId, TypeMetadataProvider},
};
use crate::server::topology::types::views::{
    FilterValueContext, HasFilterValues, MetadataFilterType,
};
use chrono::{DateTime, Utc};
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Display;
use strum_macros::{EnumIter, IntoStaticStr};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

/// Which groups of per-interface data the daemon read in full during a scan.
///
/// Each group comes from its own SNMP walk, and a walk cut short by a timeout yields exactly the
/// same empty result as a device that genuinely has nothing to report. Without knowing which
/// happened, the server overwrote good data with NULL on every truncation — and for the neighbour
/// fields that also dropped the row out of L2 resolution permanently, since the resolution filter
/// requires a chassis id or CDP device id to be present.
///
/// Every field defaults to `true`, so a daemon predating this behaves exactly as before: it
/// reports everything as authoritative and the server overwrites.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct InterfaceDataComplete {
    /// `lldp_chassis_id`, `lldp_port_id`, `lldp_sys_name`, `lldp_port_desc`, `lldp_mgmt_addr`,
    /// `lldp_sys_desc`
    #[serde(default = "crate::server::interfaces::r#impl::base::complete_default")]
    pub lldp: bool,
    /// `cdp_device_id`, `cdp_port_id`, `cdp_platform`, `cdp_address`
    #[serde(default = "crate::server::interfaces::r#impl::base::complete_default")]
    pub cdp: bool,
    /// `fdb_macs`
    #[serde(default = "crate::server::interfaces::r#impl::base::complete_default")]
    pub fdb: bool,
    /// `native_vlan_id`, `vlan_ids`
    #[serde(default = "crate::server::interfaces::r#impl::base::complete_default")]
    pub vlan_membership: bool,
}

pub(crate) fn complete_default() -> bool {
    true
}

impl Default for InterfaceDataComplete {
    fn default() -> Self {
        Self {
            lldp: true,
            cdp: true,
            fdb: true,
            vlan_membership: true,
        }
    }
}

impl InterfaceDataComplete {
    /// Whether every group was read in full.
    pub fn all(&self) -> bool {
        self.lldp && self.cdp && self.fdb && self.vlan_membership
    }

    /// No group has been read yet, so the server keeps everything it already holds.
    ///
    /// The counterpart to [`Default`], which claims every group is authoritative. That default is
    /// right for the wire (an old daemon that never sends the field behaved that way), and wrong
    /// for a checkpoint written partway through a collection: SNMP persists its interface set as
    /// soon as the ifTable walk finishes, long before the neighbour and VLAN walks run, and
    /// shipping the all-`true` default alongside it told the server those columns were
    /// authoritatively empty. It cleared them — and an interface with no chassis id drops out of
    /// L2 resolution for good.
    pub fn none() -> Self {
        Self {
            lldp: false,
            cdp: false,
            fdb: false,
            vlan_membership: false,
        }
    }
}

/// Resolved LLDP/CDP neighbor connection.
///
/// Represents the remote endpoint this port connects to, discovered via LLDP or CDP.
/// The two variants are mutually exclusive and represent different resolution states.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
#[serde(tag = "type", content = "id")]
pub enum Neighbor {
    /// Full resolution - the specific remote port was identified
    #[schema(title = "Interface")]
    Interface(Uuid),
    /// Partial resolution - the remote device was identified but not the specific port
    #[schema(title = "Host")]
    Host(Uuid),
}

impl Neighbor {
    /// Get the Interface ID if this is a full resolution
    pub fn interface_id(&self) -> Option<Uuid> {
        match self {
            Neighbor::Interface(id) => Some(*id),
            Neighbor::Host(_) => None,
        }
    }

    /// Returns true if this is a full resolution (specific port known)
    pub fn is_full_resolution(&self) -> bool {
        matches!(self, Neighbor::Interface(_))
    }

    /// Returns true if this is a partial resolution (only host known)
    pub fn is_partial_resolution(&self) -> bool {
        matches!(self, Neighbor::Host(_))
    }
}

/// Whether a port resolved to a neighbour, for the `LinkState` metadata filter on Interface.
///
/// The L2 view draws one element per row of a device's SNMP ifTable, so its node count scales with
/// total port count rather than device count: a network of ~700 devices produced 17,236 nodes
/// against 857 links, because most of those ports are unused access ports and virtual adapters.
/// Nearly all of them carry no adjacency and so contribute nothing to the fabric the view exists
/// to show — but they are not noise either. A down access port is exactly what an operator looks
/// at when asking why something is unreachable, so this classifies rather than discards: the view
/// hides unlinked ports by default and the filter panel shows them again on one click.
///
/// `Linked` covers partial resolution as well as full. A neighbour known only at device level
/// still draws an edge (`NeighborLink` rather than `PhysicalLink`), so the port is visibly
/// connected and hiding it would break the diagram.
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    IntoStaticStr,
    EnumIter,
    ToSchema,
)]
pub enum InterfaceLinkState {
    Linked,
    Unlinked,
}

impl InterfaceLinkState {
    /// Classify a port from evidence in **both** directions.
    ///
    /// A link is recorded on one side only, so an interface reporting no neighbour of its own is
    /// still linked when something points at it. There is no outbound-only constructor on purpose:
    /// the previous one existed, was never called, and encoded exactly the mistake the frontend
    /// shipped — judging the local `neighbor` alone drew 11 edges where it should have drawn 720.
    ///
    /// A partial resolution (`Neighbor::Host` — remote device known but not the port) counts as
    /// linked: it still draws an edge, so hiding it would break the diagram.
    pub fn classify(neighbor: Option<&Neighbor>, referenced_as_neighbour: bool) -> Self {
        if neighbor.is_some() || referenced_as_neighbour {
            Self::Linked
        } else {
            Self::Unlinked
        }
    }
}

impl HasFilterValues for Interface {
    fn filter_values(&self, ctx: &FilterValueContext) -> BTreeMap<MetadataFilterType, String> {
        let state = InterfaceLinkState::classify(
            self.base.neighbor.as_ref(),
            ctx.interfaces_referenced_as_neighbours.contains(&self.id),
        );
        BTreeMap::from([(MetadataFilterType::LinkState, state.id().to_string())])
    }
}

impl HasId for InterfaceLinkState {
    fn id(&self) -> &'static str {
        self.into()
    }
}

impl EntityMetadataProvider for InterfaceLinkState {
    fn color(&self) -> Color {
        match self {
            Self::Linked => Color::Green,
            Self::Unlinked => Color::Gray,
        }
    }
    fn icon(&self) -> Icon {
        match self {
            Self::Linked => Icon::Cable,
            Self::Unlinked => Icon::Circle,
        }
    }
}

impl TypeMetadataProvider for InterfaceLinkState {
    fn name(&self) -> &'static str {
        match self {
            Self::Linked => "Linked",
            Self::Unlinked => "Unlinked",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::Linked => "Ports with a discovered neighbour",
            Self::Unlinked => "Ports with no discovered neighbour",
        }
    }
}

/// SNMP ifAdminStatus values per IF-MIB RFC 2863
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash, Default, ToSchema)]
#[repr(i32)]
pub enum IfAdminStatus {
    #[default]
    Up = 1,
    Down = 2,
    Testing = 3,
}

impl From<i32> for IfAdminStatus {
    fn from(value: i32) -> Self {
        match value {
            1 => IfAdminStatus::Up,
            2 => IfAdminStatus::Down,
            3 => IfAdminStatus::Testing,
            _ => IfAdminStatus::Up,
        }
    }
}

impl From<IfAdminStatus> for i32 {
    fn from(value: IfAdminStatus) -> Self {
        value as i32
    }
}

/// SNMP ifOperStatus values per IF-MIB RFC 2863
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    Hash,
    Default,
    ToSchema,
    strum_macros::Display,
)]
#[repr(i32)]
pub enum IfOperStatus {
    #[default]
    Up = 1,
    Down = 2,
    Testing = 3,
    Unknown = 4,
    Dormant = 5,
    NotPresent = 6,
    LowerLayerDown = 7,
}

impl From<i32> for IfOperStatus {
    fn from(value: i32) -> Self {
        match value {
            1 => IfOperStatus::Up,
            2 => IfOperStatus::Down,
            3 => IfOperStatus::Testing,
            4 => IfOperStatus::Unknown,
            5 => IfOperStatus::Dormant,
            6 => IfOperStatus::NotPresent,
            7 => IfOperStatus::LowerLayerDown,
            _ => IfOperStatus::Unknown,
        }
    }
}

impl From<IfOperStatus> for i32 {
    fn from(value: IfOperStatus) -> Self {
        value as i32
    }
}

#[derive(Debug, Clone, Validate, Serialize, Deserialize, Eq, PartialEq, Hash, ToSchema)]
pub struct InterfaceBase {
    /// The host this entity belongs to.
    pub host_id: Uuid,
    /// The network this entity belongs to.
    pub network_id: Uuid,
    /// SNMP ifIndex - stable identifier within device
    pub if_index: i32,
    /// SNMP ifDescr - interface description (e.g., GigabitEthernet0/1)
    #[validate(length(min = 1, message = "Interface description is required"))]
    pub if_descr: String,
    /// SNMP ifName - short interface name (e.g., Gi1/0/1)
    pub if_name: Option<String>,
    /// SNMP ifAlias - user-configured description
    pub if_alias: Option<String>,
    /// SNMP ifType - IANAifType integer (6=ethernet, 24=loopback, etc.)
    pub if_type: i32,
    /// Interface speed from ifSpeed/ifHighSpeed in bits per second
    pub speed_bps: Option<i64>,
    /// SNMP ifAdminStatus: 1=up, 2=down, 3=testing
    pub admin_status: IfAdminStatus,
    /// SNMP ifOperStatus: 1=up, 2=down, 3=testing, 4=unknown, 5=dormant, 6=notPresent, 7=lowerLayerDown
    pub oper_status: IfOperStatus,

    // Local links
    /// MAC address from SNMP ifPhysAddress - immutable once set
    #[serde(default)]
    #[schema(value_type = Option<String>, pattern = r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", example = "a4:bb:6d:12:34:56")]
    pub mac_address: Option<MacAddress>,
    /// FK to IPAddress entity - this port's IP assignment (must be on same host).
    /// Old daemons send this as "interface_id".
    #[serde(alias = "interface_id")]
    pub ip_address_id: Option<Uuid>,

    // Neighbor resolution (LLDP/CDP) - remote endpoint this port connects to
    /// Resolved neighbor connection (mutually exclusive: either Interface or Host)
    pub neighbor: Option<Neighbor>,
    /// When a scan last carried evidence that something is adjacent to this port.
    ///
    /// The freshness subject for the *link*, as `last_seen_at` is for the port. A port keeps
    /// appearing in the ifTable long after its neighbour record stops arriving, so `last_seen_at`
    /// cannot tell a live adjacency from one whose evidence has vanished. Judged against the same
    /// `Network::stale_cutoff` as every other freshness verdict.
    ///
    /// `None` means no scan has ever carried evidence for this row, and reads as *unknown* —
    /// never as stale. Server-owned: stamped on the discovery ingest path, never sent by a daemon.
    #[serde(default)]
    #[schema(read_only)]
    pub neighbor_seen_at: Option<DateTime<Utc>>,

    // Raw LLDP data (from SNMP lldpRemTable, used for resolution and display)
    /// Remote chassis identifier from LLDP neighbor (globally/locally unique)
    pub lldp_chassis_id: Option<LldpChassisId>,
    /// Remote port identifier from LLDP neighbor
    pub lldp_port_id: Option<LldpPortId>,
    /// Remote system name from LLDP neighbor (lldpRemSysName)
    pub lldp_sys_name: Option<String>,
    /// Remote port description from LLDP neighbor (lldpRemPortDesc)
    pub lldp_port_desc: Option<String>,
    /// Remote management IP from LLDP neighbor (lldpRemManAddr). IPv4 or IPv6.
    #[schema(value_type = Option<String>, example = "192.168.1.1")]
    pub lldp_mgmt_addr: Option<std::net::IpAddr>,
    /// Remote system description from LLDP neighbor (lldpRemSysDesc) - platform info
    pub lldp_sys_desc: Option<String>,

    // Raw CDP data (from SNMP cdpCacheTable, Cisco devices)
    /// Remote device ID from CDP (typically hostname, locally unique)
    pub cdp_device_id: Option<String>,
    /// Remote port ID from CDP
    pub cdp_port_id: Option<String>,
    /// Remote platform from CDP (e.g., "Cisco IOS")
    pub cdp_platform: Option<String>,
    /// Remote management IP from CDP (cdpCacheAddress). IPv4 or IPv6.
    #[schema(value_type = Option<String>, example = "192.168.1.1")]
    pub cdp_address: Option<std::net::IpAddr>,

    /// Bridge FDB: learned MAC addresses on this switch port.
    /// Single-MAC ports can be resolved to neighbor links server-side.
    /// Multi-MAC ports indicate uplinks where LLDP/CDP is the better source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fdb_macs: Option<Vec<String>>,

    /// Native/untagged VLAN entity ID on this port (resolved from Q-BRIDGE dot1qPvid)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_vlan_id: Option<Uuid>,

    /// Tagged VLAN entity IDs on this port (resolved from Q-BRIDGE dot1qVlanCurrentEgressPorts)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan_ids: Option<Vec<Uuid>>,
}

impl Default for InterfaceBase {
    fn default() -> Self {
        Self {
            host_id: Uuid::nil(),
            network_id: Uuid::nil(),
            if_index: 0,
            if_descr: String::new(),
            if_name: None,
            if_alias: None,
            if_type: 1, // other
            speed_bps: None,
            admin_status: IfAdminStatus::Up,
            oper_status: IfOperStatus::Up,
            mac_address: None,
            ip_address_id: None,
            neighbor: None,
            neighbor_seen_at: None,
            lldp_chassis_id: None,
            lldp_port_id: None,
            lldp_sys_name: None,
            lldp_port_desc: None,
            lldp_mgmt_addr: None,
            lldp_sys_desc: None,
            cdp_device_id: None,
            cdp_port_id: None,
            cdp_platform: None,
            cdp_address: None,
            fdb_macs: None,
            native_vlan_id: None,
            vlan_ids: None,
        }
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, Default, ToSchema, Validate,
)]
pub struct Interface {
    /// Server-assigned unique identifier.
    #[serde(default)]
    #[schema(read_only, required)]
    pub id: Uuid,
    /// When this record was first created.
    #[serde(default)]
    #[schema(read_only, required)]
    pub created_at: DateTime<Utc>,
    /// When this record was last modified.
    #[serde(default)]
    #[schema(read_only, required)]
    pub updated_at: DateTime<Utc>,
    /// Start of the interval this revision was current for (SCD2 history).
    #[serde(default)]
    #[schema(read_only)]
    pub valid_from: DateTime<Utc>,
    /// End of the interval this revision was current for. `null` while it is the live revision.
    #[serde(default)]
    #[schema(read_only)]
    pub valid_to: Option<DateTime<Utc>>,
    /// Stable identifier shared by every revision of the same entity across its history.
    #[serde(default)]
    #[schema(read_only)]
    pub lineage_id: Option<Uuid>,
    /// When a discovery last observed this entity.
    #[serde(default)]
    #[schema(read_only)]
    pub last_seen_at: DateTime<Utc>,
    /// The most recent discovery that observed this entity.
    #[serde(default)]
    #[schema(read_only)]
    pub last_discovery_id: Option<Uuid>,
    /// The discovery that first observed this entity.
    #[serde(default)]
    #[schema(read_only)]
    pub first_discovery_id: Option<Uuid>,
    #[serde(flatten)]
    #[validate(nested)]
    pub base: InterfaceBase,
}

impl ChangeTriggersTopologyStaleness<Interface> for Interface {
    fn triggers_staleness(&self, other: Option<Interface>) -> bool {
        if let Some(other_entry) = other {
            // Topology changes if neighbor changes (link discovery)
            self.base.neighbor != other_entry.base.neighbor
                || self.base.ip_address_id != other_entry.base.ip_address_id
                || self.base.host_id != other_entry.base.host_id
        } else {
            true // New or deleted entry triggers staleness
        }
    }
}

impl Display for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Interface {} (ifIndex {}): {}",
            self.id, self.base.if_index, self.base.if_descr
        )
    }
}

impl Interface {
    pub fn new(base: InterfaceBase) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            base,
        }
    }

    /// Returns true if interface is operationally up
    pub fn is_up(&self) -> bool {
        self.base.oper_status == IfOperStatus::Up
    }

    /// Returns true if interface is administratively up
    pub fn is_admin_up(&self) -> bool {
        self.base.admin_status == IfAdminStatus::Up
    }

    /// Get display name - prefer ifAlias if set, otherwise ifDescr
    pub fn display_name(&self) -> &str {
        self.base.if_alias.as_deref().unwrap_or(&self.base.if_descr)
    }

    /// Returns true if this port has a resolved neighbor connection
    pub fn has_neighbor(&self) -> bool {
        self.base.neighbor.is_some()
    }

    /// Returns true if neighbor is fully resolved (remote port known)
    pub fn has_full_neighbor_resolution(&self) -> bool {
        self.base
            .neighbor
            .as_ref()
            .map(|n| n.is_full_resolution())
            .unwrap_or(false)
    }

    /// Returns true if this port has raw LLDP data (may or may not be resolved)
    pub fn has_lldp_data(&self) -> bool {
        self.base.lldp_chassis_id.is_some() || self.base.lldp_port_id.is_some()
    }

    /// Returns true if this port has raw CDP data (may or may not be resolved)
    pub fn has_cdp_data(&self) -> bool {
        self.base.cdp_device_id.is_some() || self.base.cdp_port_id.is_some()
    }

    /// Returns true if this port has any neighbor discovery data (LLDP or CDP)
    pub fn has_neighbor_discovery_data(&self) -> bool {
        self.has_lldp_data() || self.has_cdp_data()
    }

    /// Whether this row carries evidence that *something* is adjacent to this port.
    ///
    /// The two sources L2 resolution actually consumes: an identity the ladder can look up, and a
    /// bridge-FDB port that learned exactly one address. Deliberately narrower than
    /// [`Self::has_neighbor_discovery_data`] — a port id or a port description names a port on a
    /// device this row cannot identify, so on its own it is not evidence that anything is there,
    /// and the resolution filter would skip the row anyway.
    ///
    /// Defers to [`InterfaceBase::has_resolvable_identity`] rather than restating it: this used to
    /// be a sixth hand-written copy of the same column list, and "carries evidence" and "is worth
    /// resolving" answering differently for one row is how a link goes stale while the resolution
    /// pass still believes in it.
    pub fn has_neighbor_evidence(&self) -> bool {
        self.base.has_resolvable_identity() || self.base.has_single_fdb_mac()
    }

    /// Record the last scan that actually saw a neighbour on this port.
    ///
    /// Must be called on the raw incoming row, *before* [`Self::preserve_uncollected_data`]: after
    /// it, this row's LLDP/CDP/FDB identifiers may be the previous scan's, put back because this
    /// scan could not read them. Stamping from those would make a link whose neighbour walk has
    /// been failing for a month look freshly evidenced on every scan — the exact reading this
    /// column exists to make impossible.
    ///
    /// A scan that carried nothing leaves the stored value alone, so the column always names the
    /// last scan that saw a neighbour rather than the last scan that ran. It stays `None` for a row
    /// no scan has ever had evidence for, which reads as unknown.
    pub fn stamp_neighbor_evidence(&mut self, existing: Option<&Self>) {
        self.base.neighbor_seen_at = if self.has_neighbor_evidence() {
            // `last_seen_at` is the submission's canonical scan_time, so every temporal column on
            // the row lines up at one instant.
            Some(self.last_seen_at)
        } else {
            existing.and_then(|e| e.base.neighbor_seen_at)
        };
    }

    /// Keep the stored values for any group of data this scan did not finish reading.
    ///
    /// Each group of neighbour/VLAN fields comes from its own SNMP walk, and a walk cut short by a
    /// timeout returns exactly what a device with nothing to report returns: nothing. Overwriting
    /// on that is destructive rather than merely stale — losing `lldp_chassis_id` also drops the
    /// row out of L2 resolution (the pass requires a chassis id or CDP device id), so the link
    /// freezes at whatever it last resolved to and no rescan can repair it.
    ///
    /// A group the daemon *did* read in full is authoritative in both directions: absence means
    /// the neighbour is genuinely gone and must be cleared, or a decommissioned link lingers for
    /// ever.
    pub fn preserve_uncollected_data(&mut self, existing: &Self, collected: InterfaceDataComplete) {
        if !collected.lldp {
            self.base.lldp_chassis_id = existing.base.lldp_chassis_id.clone();
            self.base.lldp_port_id = existing.base.lldp_port_id.clone();
            self.base.lldp_sys_name = existing.base.lldp_sys_name.clone();
            self.base.lldp_port_desc = existing.base.lldp_port_desc.clone();
            self.base.lldp_mgmt_addr = existing.base.lldp_mgmt_addr;
            self.base.lldp_sys_desc = existing.base.lldp_sys_desc.clone();
        }
        if !collected.cdp {
            self.base.cdp_device_id = existing.base.cdp_device_id.clone();
            self.base.cdp_port_id = existing.base.cdp_port_id.clone();
            self.base.cdp_platform = existing.base.cdp_platform.clone();
            self.base.cdp_address = existing.base.cdp_address;
        }
        if !collected.fdb {
            self.base.fdb_macs = existing.base.fdb_macs.clone();
        }
        if !collected.vlan_membership {
            self.base.native_vlan_id = existing.base.native_vlan_id;
            self.base.vlan_ids = existing.base.vlan_ids.clone();
        }
    }

    /// Drop identity fields the device reported blank, so absence is recorded as absence.
    ///
    /// A zero-length ifXTable `ifName` is a legitimate SNMP answer meaning "this device has no
    /// name for this port", but it reaches the server as `Some("")` and from there is treated as
    /// a real name: the tiered discovery match keys on `if_name.is_some()`, and the partial unique
    /// index `(host_id, if_name) WHERE if_name IS NOT NULL` counts `""` as a value. A switch that
    /// answers `""` for every port then hits a duplicate-key violation on its second port —
    /// truncating that host's whole ingest. `if_index` remains as the identity for such ports,
    /// which is the correct one anyway.
    ///
    /// Called on the discovery ingest path so devices behind older daemons are covered too.
    pub fn normalize_blank_identity(&mut self) {
        if self
            .base
            .if_name
            .as_deref()
            .is_some_and(|name| name.trim().is_empty())
        {
            self.base.if_name = None;
        }
        if self
            .base
            .if_alias
            .as_deref()
            .is_some_and(|alias| alias.trim().is_empty())
        {
            self.base.if_alias = None;
        }
    }

    /// Whether this row's remote *port*, if resolved, could only have been matched on a MAC.
    ///
    /// The two sources that identify a far-end port by MAC and nothing else: an LLDP port id of
    /// subtype 3 (`macAddress`), and a bridge-FDB port that learned exactly one address. Both are
    /// only as good as the MAC's uniqueness on the far-end device, which is what makes them the
    /// bindings worth re-examining after that rule was tightened (GH #668). Every other tier
    /// matches on a name, an ifIndex or an IP and is unaffected.
    pub fn port_bound_by_mac(&self) -> bool {
        if matches!(self.base.lldp_port_id, Some(LldpPortId::MacAddress(_))) {
            return true;
        }

        // FDB resolution only claims rows with no identity to resolve and exactly one learned MAC.
        // Stated as the negation of the shared predicate rather than as its own column list, which
        // is what it used to be — and it was already a column short of the two sites that spelled
        // the same rule out with `cdp_address` in it.
        !self.base.has_resolvable_identity() && self.base.has_single_fdb_mac()
    }
}

/// Common IANAifType values for reference
/// Full list: https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
pub mod if_type {
    pub const OTHER: i32 = 1;
    pub const ETHERNET_CSMA_CD: i32 = 6;
    pub const ISO88023_CSMA_CD: i32 = 7;
    pub const FAST_ETHERNET: i32 = 62;
    pub const GIGABIT_ETHERNET: i32 = 117;
    pub const SOFTWARE_LOOPBACK: i32 = 24;
    pub const TUNNEL: i32 = 131;
    pub const PROP_VIRTUAL: i32 = 53;
    pub const IEEE8023AD_LAG: i32 = 161; // Link Aggregation Group
    pub const BRIDGE: i32 = 209;
    pub const VLAN: i32 = 135;
    pub const L2_VLAN: i32 = 136;
    pub const L3_IPVLAN: i32 = 137;
    pub const IEEE80211: i32 = 71; // Wi-Fi

    /// The virtual/software interface families, excluded wherever a question is about a physical
    /// port: which rows the L2 view draws, and which rows count towards a MAC's uniqueness within
    /// a device.
    ///
    /// Kept here rather than beside either consumer because the two must agree. A VLAN interface
    /// carrying the chassis base MAC is not a candidate far end for a cable, so it must neither
    /// be drawn as a port nor make a physical port's address look ambiguous — the customer's
    /// Westermo has six `propVirtual` VLAN rows sharing `…02:E0` while every physical port has a
    /// unique address.
    pub const EXCLUDED_IF_TYPES: &[i32] = &[
        SOFTWARE_LOOPBACK,
        PROP_VIRTUAL,
        IEEE80211,
        TUNNEL,
        VLAN,
        L2_VLAN,
        BRIDGE,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(configure: impl FnOnce(&mut InterfaceBase)) -> Interface {
        let mut base = InterfaceBase::default();
        configure(&mut base);
        Interface::new(base)
    }

    /// Only the tiers that match on a MAC are re-examined when that MAC turns out to be shared;
    /// a port matched on its name or ifIndex was never resting on the MAC's uniqueness, and
    /// re-opening it would tear down a healthy link on every scan.
    #[test]
    fn only_a_mac_matched_port_is_worth_re_examining() {
        let by_mac = interface(|b| {
            b.lldp_chassis_id = Some(LldpChassisId::MacAddress("00:ad:24:af:4e:00".into()));
            b.lldp_port_id = Some(LldpPortId::MacAddress("00:ad:24:af:4e:00".into()));
        });
        assert!(by_mac.port_bound_by_mac());

        let by_name = interface(|b| {
            b.lldp_chassis_id = Some(LldpChassisId::MacAddress("00:ad:24:af:4e:00".into()));
            b.lldp_port_id = Some(LldpPortId::InterfaceName("Slot0/3".into()));
        });
        assert!(!by_name.port_bound_by_mac());
    }

    /// A bridge-FDB port that learned exactly one address is placed by that address and nothing
    /// else, so it rests on the same uniqueness assumption as a subtype-3 port id. More than one
    /// learned address means FDB resolution never ran on the row at all.
    #[test]
    fn a_single_mac_fdb_port_rests_on_the_same_assumption() {
        let single = interface(|b| b.fdb_macs = Some(vec!["00:ad:24:af:4e:00".into()]));
        assert!(single.port_bound_by_mac());

        let several = interface(|b| {
            b.fdb_macs = Some(vec!["00:ad:24:af:4e:00".into(), "00:ad:24:af:4e:01".into()])
        });
        assert!(!several.port_bound_by_mac());
    }

    /// A chassis id the ladder cannot look up does not make a row an LLDP row. The FDB filter
    /// selects this row — `has_resolvable_identity` is false for it — so the FDB tier is what
    /// places it, and `port_bound_by_mac` has to say so or the binding is never re-examined.
    /// Before the shared predicate these two disagreed: the filter saw an empty chassis id and
    /// this test saw a present one.
    #[test]
    fn a_blank_chassis_id_leaves_the_row_to_the_fdb_tier() {
        let blank = interface(|b| {
            b.lldp_chassis_id = Some(LldpChassisId::LocallyAssigned(String::new()));
            b.fdb_macs = Some(vec!["00:ad:24:af:4e:00".into()]);
        });
        assert!(blank.port_bound_by_mac());
    }

    /// An identifier with nothing in it is not evidence that anything is attached, so it must not
    /// keep `neighbor_seen_at` advancing on a port whose neighbour has actually gone.
    #[test]
    fn a_blank_identifier_is_not_evidence_of_a_neighbour() {
        let blank = interface(|b| {
            b.lldp_chassis_id = Some(LldpChassisId::LocallyAssigned("  ".into()));
            b.cdp_device_id = Some(String::new());
        });
        assert!(!blank.has_neighbor_evidence());

        let real = interface(|b| {
            b.lldp_chassis_id = Some(LldpChassisId::MacAddress("00:ad:24:af:4e:00".into()));
        });
        assert!(real.has_neighbor_evidence());
    }

    /// FDB resolution only claims rows with no LLDP/CDP data, so a row carrying both is judged by
    /// the protocol tier that actually placed it — here a name, which is not MAC-dependent.
    #[test]
    fn lldp_data_decides_a_row_that_also_carries_fdb_addresses() {
        let both = interface(|b| {
            b.lldp_chassis_id = Some(LldpChassisId::MacAddress("00:ad:24:af:4e:00".into()));
            b.lldp_port_id = Some(LldpPortId::InterfaceName("Slot0/3".into()));
            b.fdb_macs = Some(vec!["00:ad:24:af:4e:09".into()]);
        });
        assert!(!both.port_bound_by_mac());
    }

    /// A port whose evidence arrived this scan is stamped at that scan's instant, so the link's
    /// freshness moves with the evidence rather than with the ifTable.
    #[test]
    fn a_scan_carrying_evidence_stamps_it() {
        let previous = DateTime::parse_from_rfc3339("2026-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut existing = interface(|_| {});
        existing.base.neighbor_seen_at = Some(previous);

        let mut incoming = interface(|b| {
            b.lldp_chassis_id = Some(LldpChassisId::MacAddress("00:ad:24:af:4e:00".into()));
        });
        incoming.stamp_neighbor_evidence(Some(&existing));

        assert_eq!(incoming.base.neighbor_seen_at, Some(incoming.last_seen_at));
    }

    /// The whole point of the column: the port is still in the ifTable, so `last_seen_at` advances
    /// every scan, but nothing has said anything is attached to it since `previous`. Overwriting
    /// here would make the link permanently indistinguishable from a live one.
    #[test]
    fn a_scan_carrying_no_evidence_leaves_the_stamp_where_it_was() {
        let previous = DateTime::parse_from_rfc3339("2026-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut existing = interface(|_| {});
        existing.base.neighbor_seen_at = Some(previous);

        // What the daemon sends once the neighbour record is discarded: the port, and nothing
        // about what is on the other end of it.
        let mut incoming = interface(|_| {});
        incoming.stamp_neighbor_evidence(Some(&existing));

        assert_eq!(incoming.base.neighbor_seen_at, Some(previous));
        assert_ne!(incoming.base.neighbor_seen_at, Some(incoming.last_seen_at));
    }

    /// A port no scan has ever seen a neighbour on stays `None`, which reads as unknown. Anything
    /// else would flag every row predating the column the moment it ships.
    #[test]
    fn a_port_that_never_had_a_neighbour_is_never_stamped() {
        let mut incoming = interface(|_| {});
        incoming.stamp_neighbor_evidence(None);

        assert_eq!(incoming.base.neighbor_seen_at, None);
    }

    /// A port id names a port on a device this row cannot identify, and a multi-address FDB port
    /// names nothing at all — neither says anything is adjacent, and L2 resolution consumes
    /// neither. Stamping on them would keep a link looking evidenced by data that cannot draw it.
    #[test]
    fn an_identifier_resolution_cannot_use_is_not_evidence() {
        let port_id_only = interface(|b| {
            b.lldp_port_id = Some(LldpPortId::InterfaceName("Slot0/3".into()));
            b.lldp_port_desc = Some("uplink".into());
        });
        assert!(!port_id_only.has_neighbor_evidence());

        let many_macs = interface(|b| {
            b.fdb_macs = Some(vec!["00:ad:24:af:4e:00".into(), "00:ad:24:af:4e:01".into()])
        });
        assert!(!many_macs.has_neighbor_evidence());
    }

    /// The ordering `create_or_update_from_discovery` depends on. `preserve_uncollected_data` puts
    /// the previous scan's identifiers back when a walk was cut short, and stamping from those
    /// would call a link freshly evidenced every scan while its neighbour walk has in fact been
    /// failing for a month.
    #[test]
    fn a_walk_that_was_cut_short_does_not_stamp() {
        let previous = DateTime::parse_from_rfc3339("2026-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut existing = interface(|b| {
            b.lldp_chassis_id = Some(LldpChassisId::MacAddress("00:ad:24:af:4e:00".into()));
        });
        existing.base.neighbor_seen_at = Some(previous);

        // A cut-short walk returns what a device with nothing to report returns.
        let mut incoming = interface(|_| {});
        incoming.stamp_neighbor_evidence(Some(&existing));
        incoming.preserve_uncollected_data(
            &existing,
            InterfaceDataComplete {
                lldp: false,
                ..Default::default()
            },
        );

        assert_eq!(
            incoming.base.lldp_chassis_id, existing.base.lldp_chassis_id,
            "the restore this test exists to run ahead of must actually have happened"
        );
        assert_eq!(incoming.base.neighbor_seen_at, Some(previous));
    }
}
