//! LLDP/FDB neighbor-resolution filters.
use super::*;
use crate::server::interfaces::r#impl::base::if_type::EXCLUDED_IF_TYPES;
use crate::server::interfaces::r#impl::identity::{
    sql_has_no_resolvable_identity, sql_has_resolvable_identity,
};

impl<T: Storable> StorableFilter<T> {
    // =========================================================================
    // LLDP resolution filters
    // =========================================================================

    /// Filter by IP address (for ip_addresses table)
    pub fn ip_address(mut self, ip: std::net::IpAddr) -> Self {
        let col = self.qualify_column("ip_address");
        self.conditions
            .push(format!("{} = ${}", col, self.values.len() + 1));
        self.values.push(SqlValue::IpAddr(ip));
        self
    }

    /// Filter by if_descr (for interfaces table)
    pub fn if_descr(mut self, descr: &str) -> Self {
        let col = self.qualify_column("if_descr");
        self.conditions
            .push(format!("{} = ${}", col, self.values.len() + 1));
        self.values.push(SqlValue::String(descr.to_string()));
        self
    }

    /// Filter by if_name (for interfaces table)
    pub fn if_name(mut self, name: &str) -> Self {
        let col = self.qualify_column("if_name");
        self.conditions
            .push(format!("{} = ${}", col, self.values.len() + 1));
        self.values.push(SqlValue::String(name.to_string()));
        self
    }

    /// Filter by if_alias (for interfaces table)
    ///
    /// `ifAlias` is the operator-assigned description (`ifXTable`), and on several families it is
    /// the only column carrying the bare port name: the Westermo WeOS switches report
    /// `ifDescr = "100-T eth9"` (media type prefixed) while `ifName` and `ifAlias` both hold
    /// `eth9`. Non-unique by nature — it is user-configurable — so every caller resolves it on a
    /// single match only.
    pub fn if_alias(mut self, alias: &str) -> Self {
        let col = self.qualify_column("if_alias");
        self.conditions
            .push(format!("{} = ${}", col, self.values.len() + 1));
        self.values.push(SqlValue::String(alias.to_string()));
        self
    }

    /// Restrict to interfaces that are physical ports, excluding the virtual/software families.
    ///
    /// A device's VLAN and loopback rows routinely repeat the chassis base MAC that no physical
    /// port carries — the customer's Westermo has six `propVirtual` VLAN interfaces sharing
    /// `…02:E0` while all ten physical ports have unique addresses. Counting those rows against a
    /// MAC-uniqueness test makes a lookup ambiguous that no port would have contested, so the test
    /// is scoped to the rows that can actually be the far end of a cable.
    ///
    pub fn physical_if_types(mut self) -> Self {
        let col = self.qualify_column("if_type");
        let start = self.values.len() + 1;
        let placeholders: Vec<String> = (start..start + EXCLUDED_IF_TYPES.len())
            .map(|i| format!("${i}"))
            .collect();
        self.conditions
            .push(format!("{col} NOT IN ({})", placeholders.join(", ")));
        for if_type in EXCLUDED_IF_TYPES {
            self.values.push(SqlValue::I32(*if_type));
        }
        self
    }

    /// Filter by if_index (for interfaces table)
    pub fn if_index(mut self, if_index: i32) -> Self {
        let col = self.qualify_column("if_index");
        self.conditions
            .push(format!("{} = ${}", col, self.values.len() + 1));
        self.values.push(SqlValue::I32(if_index));
        self
    }

    /// Filter by chassis_id (for hosts table)
    pub fn chassis_id(mut self, chassis_id: &str) -> Self {
        let col = self.qualify_column("chassis_id");
        self.conditions
            .push(format!("{} = ${}", col, self.values.len() + 1));
        self.values.push(SqlValue::String(chassis_id.to_string()));
        self
    }

    /// Filter by sys_name (for hosts table)
    pub fn sys_name(mut self, sys_name: &str) -> Self {
        let col = self.qualify_column("sys_name");
        self.conditions
            .push(format!("{} = ${}", col, self.values.len() + 1));
        self.values.push(SqlValue::String(sys_name.to_string()));
        self
    }

    /// Filter by ip_address_id FK (for interfaces table)
    pub fn ip_address_id(mut self, ip_address_id: &Uuid) -> Self {
        let col = self.qualify_column("ip_address_id");
        self.conditions
            .push(format!("{} = ${}", col, self.values.len() + 1));
        self.values.push(SqlValue::Uuid(*ip_address_id));
        self
    }

    /// Filter interfaces whose LLDP/CDP neighbor is not yet fully resolved, in a network.
    ///
    /// Admits both never-resolved rows (no neighbor at all) and *partially* resolved rows
    /// (`neighbor_host_id` set, remote port still unknown). A partial resolution is invisible in
    /// the L2 view — only `Neighbor::Interface` renders an edge — so leaving those rows out of the
    /// pass, as the original "both columns NULL" predicate did, made a partial permanent: a port
    /// whose remote interface became resolvable later (new port-ID strategy, remote host rescanned)
    /// was never looked at again. The resolution loop retries only the port half for those rows and
    /// never downgrades an existing partial.
    ///
    /// Scoped to live SCD2 rows: snapshot close-and-clone leaves closed historical copies of these
    /// interfaces behind, and resolving/updating those would both waste the pass and mutate history.
    ///
    /// "Names a neighbour" is `InterfaceBase::has_resolvable_identity`, rendered into SQL from
    /// the same column list the Rust predicate reads, so this filter cannot select a row the
    /// resolution loop will then throw away unjudged.
    ///
    /// **Currently unused.** The resolution pass reads
    /// [`Self::lldp_neighbors_in_network`] — its superset — and re-examines already-bound rows
    /// rather than skipping them, which is what this filter's `neighbor_interface_id IS NULL`
    /// clause would do. Kept and kept correct because `re_examine_port_binding` documents its
    /// scoping against this predicate, but nothing calls it; it is not a second live definition of
    /// anything.
    pub fn unresolved_lldp_port_in_network(mut self, network_id: Uuid) -> Self {
        let network_col = self.qualify_column("network_id");
        let has_identity = sql_has_resolvable_identity(|c| self.qualify_column(c));
        let neighbor_if_entry_col = self.qualify_column("neighbor_interface_id");

        self.conditions
            .push(format!("{} = ${}", network_col, self.values.len() + 1));
        self.values.push(SqlValue::Uuid(network_id));

        // Names a neighbour the ladder has a strategy for...
        self.conditions.push(has_identity);
        // ...but no remote port yet (unresolved, or resolved only as far as the host)
        self.conditions
            .push(format!("{} IS NULL", neighbor_if_entry_col));

        self.live()
    }

    /// Every interface in a network that names a neighbour, whatever state its resolution is in.
    ///
    /// The superset of [`Self::unresolved_lldp_port_in_network`] and
    /// [`Self::port_resolved_by_mac_in_network`], and the input to the reciprocal-pairing tier:
    /// deciding that host A names host B on exactly one port has to count *every* port that names
    /// it, not just the ones still unresolved. Counting only the unresolved half would pair one
    /// leg of a LAG whose other leg happened to resolve, which is the arbitrary-port outcome the
    /// MAC guard exists to prevent.
    ///
    /// Bounded by adjacencies rather than by interfaces — a switch contributes one row per port
    /// that sees something, not one per port.
    ///
    /// The superset is *composed*, not restated: `InterfaceBase::has_resolvable_identity` in SQL,
    /// OR an already-stored neighbour. Spelling the identity half out again here is what let this
    /// filter admit rows on `cdp_address` — a management address the resolution ladder has no arm
    /// for — while the FDB filter and the MAC-binding test, writing the same rule by hand, did not.
    pub fn lldp_neighbors_in_network(mut self, network_id: Uuid) -> Self {
        let network_col = self.qualify_column("network_id");
        let has_identity = sql_has_resolvable_identity(|c| self.qualify_column(c));
        let neighbor_if_entry_col = self.qualify_column("neighbor_interface_id");
        let neighbor_host_col = self.qualify_column("neighbor_host_id");

        self.conditions
            .push(format!("{} = ${}", network_col, self.values.len() + 1));
        self.values.push(SqlValue::Uuid(network_id));

        self.conditions.push(format!(
            "({has_identity} OR {neighbor_if_entry_col} IS NOT NULL \
             OR {neighbor_host_col} IS NOT NULL)"
        ));

        self.live()
    }

    /// Filter interfaces with unresolved single-MAC FDB data in a network.
    /// Matches entries that have exactly 1 learned MAC, no existing neighbor, and no identity the
    /// LLDP/CDP ladder could resolve (FDB is lower-priority than protocol-based discovery).
    ///
    /// The "no identity" half is the negation of `InterfaceBase::has_resolvable_identity`, which
    /// is what keeps this filter and `Interface::port_bound_by_mac` — the test for whether a
    /// binding *came* from this tier — asking the same question of the same row.
    pub fn unresolved_fdb_in_network(mut self, network_id: Uuid) -> Self {
        let network_col = self.qualify_column("network_id");
        let fdb_col = self.qualify_column("fdb_macs");
        let neighbor_if_entry_col = self.qualify_column("neighbor_interface_id");
        let neighbor_host_col = self.qualify_column("neighbor_host_id");
        let no_identity = sql_has_no_resolvable_identity(|c| self.qualify_column(c));

        self.conditions
            .push(format!("{} = ${}", network_col, self.values.len() + 1));
        self.values.push(SqlValue::Uuid(network_id));

        // Has single-MAC FDB data, no neighbor, nothing for the protocol ladder to resolve
        self.conditions.push(format!(
            "{} IS NOT NULL AND jsonb_array_length({}) = 1",
            fdb_col, fdb_col
        ));
        self.conditions
            .push(format!("{} IS NULL", neighbor_if_entry_col));
        self.conditions
            .push(format!("{} IS NULL", neighbor_host_col));
        self.conditions.push(no_identity);

        self.live()
    }

    /// Filter interfaces that have any resolved neighbor (full or partial resolution)
    pub fn has_neighbor(mut self) -> Self {
        let neighbor_if_entry_col = self.qualify_column("neighbor_interface_id");
        let neighbor_host_col = self.qualify_column("neighbor_host_id");

        self.conditions.push(format!(
            "({} IS NOT NULL OR {} IS NOT NULL)",
            neighbor_if_entry_col, neighbor_host_col
        ));

        self
    }

    /// Filter interfaces with full neighbor resolution (specific remote port known)
    pub fn has_neighbor_if_entry(mut self) -> Self {
        let col = self.qualify_column("neighbor_interface_id");
        self.conditions.push(format!("{} IS NOT NULL", col));
        self
    }

    /// Filter interfaces connected to a specific host (either resolution type)
    pub fn neighbor_host(mut self, host_id: Uuid) -> Self {
        let neighbor_if_entry_col = self.qualify_column("neighbor_interface_id");
        let neighbor_host_col = self.qualify_column("neighbor_host_id");

        // Either directly connected to host (partial resolution)
        // Or connected to an interface on that host (full resolution)
        // For full resolution, we need a subquery
        self.conditions.push(format!(
            "({} = ${} OR {} IN (SELECT id FROM interfaces WHERE host_id = ${}))",
            neighbor_host_col,
            self.values.len() + 1,
            neighbor_if_entry_col,
            self.values.len() + 1
        ));
        self.values.push(SqlValue::Uuid(host_id));

        self
    }
}
