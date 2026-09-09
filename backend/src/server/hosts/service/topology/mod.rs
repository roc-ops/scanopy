//! LLDP and FDB link resolution.
use super::*;

use crate::daemon::discovery::types::warnings::{
    DiscoveryWarning, UnmatchedNeighbour, UnresolvedPort,
};

/// Why a far end could not be placed, carried alongside the identifiers that were tried.
///
/// The distinction is the whole point of naming these at all: `NotFound` is a gap in what has been
/// scanned and the operator can close it, `Ambiguous` is a device that *is* scanned but reports one
/// identifier for many ports, and `NoStrategy` is a gap on our side. Reporting all three as "did
/// not resolve" is what made a device-level edge un-triagable without a customer snmpwalk (GH #668).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnresolvedReason {
    NoStrategy,
    NotFound,
    Ambiguous,
}

impl UnresolvedReason {
    /// `None` for a resolution that succeeded — there is nothing to report.
    fn from_resolution(resolution: IdentityResolution) -> Option<Self> {
        match resolution {
            IdentityResolution::Resolved(_) => None,
            IdentityResolution::NoStrategy => Some(Self::NoStrategy),
            IdentityResolution::NotFound => Some(Self::NotFound),
            IdentityResolution::Ambiguous => Some(Self::Ambiguous),
        }
    }
}

/// The warning for a far end no strategy could place, or `None` when it is not worth reporting.
///
/// `NoStrategy` reaches no warning on the host side, and no longer because it is a benign
/// population worth suppressing — the `cdp_address`-only rows it used to name are not selected at
/// all now. It is a *divergence* between the guard and the chassis ladder, which is not a far end
/// anyone can go and scan, so describing it as an unmatched neighbour would misdirect the operator
/// reading the scan record. It is reported where it belongs instead:
/// [`LldpResolutionStats::ladder_divergences`], which warns.
///
/// The port side is unaffected: `UnresolvedReason::NoStrategy` there means the far end advertised
/// a port id no tier can look up, which is a real and reportable outcome — see
/// [`unresolved_port_warning`].
///
/// What each warning carries is what it takes to decide whether an unresolved neighbour is a
/// device that should have been scanned or one that never will be: which of our devices saw it, on
/// which port, and the identifier the far end advertised. That evidence used to exist only in a
/// log line, where the operator who needed it could not read it.
fn unmatched_neighbour_warning(
    interface: &Interface,
    identifier: String,
    sys_name: Option<String>,
    reason: UnresolvedReason,
) -> Option<DiscoveryWarning> {
    let detail = UnmatchedNeighbour {
        host_id: interface.base.host_id,
        if_descr: interface.base.if_descr.clone(),
        identifier,
        sys_name,
    };
    match reason {
        UnresolvedReason::NotFound => Some(DiscoveryWarning::LldpNeighbourNotFound(detail)),
        UnresolvedReason::Ambiguous => Some(DiscoveryWarning::LldpNeighbourAmbiguous(detail)),
        UnresolvedReason::NoStrategy => None,
    }
}

/// The warning for a neighbour whose far-end *device* is known but whose port is not.
///
/// This is the row that draws a device-level edge instead of a port-to-port one — the "attached to
/// the whole switch" outcome, and the harder case to reason about from a counter alone: both
/// devices are on the map and the operator has nothing left to scan. All three reasons are
/// reported, because each names a different fix.
fn unresolved_port_warning(
    interface: &Interface,
    remote_host_id: Uuid,
    port_id: Option<String>,
    reason: UnresolvedReason,
) -> DiscoveryWarning {
    let detail = UnresolvedPort {
        host_id: interface.base.host_id,
        if_descr: interface.base.if_descr.clone(),
        remote_host_id,
        port_id,
        // `lldpRemPortDesc`, the last-resort tier. Carried because "the id failed and the
        // description was empty" and "both were tried and neither matched" call for different
        // fixes.
        port_desc: interface.base.lldp_port_desc.clone(),
    };
    match reason {
        UnresolvedReason::NoStrategy => DiscoveryWarning::LldpPortNoStrategy(detail),
        UnresolvedReason::NotFound => DiscoveryWarning::LldpPortNotFound(detail),
        UnresolvedReason::Ambiguous => DiscoveryWarning::LldpPortAmbiguous(detail),
    }
}

/// Who names whom across a network's LLDP/CDP adjacencies, and the port pairs that follow from it.
///
/// Built once per resolution pass from *every* interface that names a neighbour — not just the
/// unresolved ones. The count of ports joining two devices is the whole basis of the reciprocal
/// tier, and counting only the unresolved half would pair one leg of a LAG whose other leg happened
/// to resolve, which is exactly the arbitrary-port outcome the shared-MAC guard exists to prevent.
struct NeighborAdjacency {
    /// Every interface in the network that names a neighbour, in whatever resolution state.
    interfaces: Vec<Interface>,
    /// The far-end *device* verdict per interface, computed once here and reused by the resolution
    /// pass so the chassis ladder is not run twice for the same row.
    host_of: HashMap<Uuid, IdentityResolution>,
    /// Interface id -> `(far-end interface, that interface's host)`, for pairs where each side
    /// names the other on exactly one port.
    reciprocal: HashMap<Uuid, (Uuid, Uuid)>,
}

mod reciprocal;

use reciprocal::PortBinding;

impl HostService {
    // =========================================================================
    // LLDP link resolution
    // =========================================================================

    /// Resolve LLDP links for all interfaces in a network.
    ///
    /// Called by DiscoveryService when a discovery session completes successfully.
    /// This resolves LLDP neighbor data (chassis ID, port ID) to actual database
    /// entity references via the Neighbor enum.
    ///
    /// Resolution states:
    /// - Full resolution: Both host and port identified → `Neighbor::Interface(id)`
    /// - Partial resolution: Only host identified → `Neighbor::Host(id)`
    ///
    /// Returns the statistics and the operator-facing summary of what could not be placed.
    pub async fn resolve_lldp_links(&self, network_id: Uuid) -> Result<LldpResolutionOutcome> {
        let resolver = LldpResolverImpl::new(
            self.interface_service.clone(),
            self.ip_address_service.clone(),
            self.storage.clone(),
        );

        // The instant before which neighbour evidence counts as stale, from the network's own
        // window — the same helper the `?stale=` list filter uses, so a link and a host cannot
        // disagree about what stale means. A network that no longer exists yields no cutoff, and
        // the fallback makes every row read current: an orphaned FK must never tear bindings down.
        let evidence_cutoff = self
            .network_service
            .stale_cutoffs(&[network_id])
            .await?
            .into_iter()
            .find(|(id, _)| *id == network_id)
            .map(|(_, cutoff)| cutoff)
            .unwrap_or(DateTime::<Utc>::MIN_UTC);

        // Who names whom, and which of those pairs are unambiguous in both directions. Computed
        // before anything is written, because it is the authority both for the reciprocal tier
        // below and for deciding whether an existing MAC-matched binding still stands.
        let mut adjacency = self
            .build_neighbor_adjacency(network_id, &resolver, evidence_cutoff)
            .await?;
        let reciprocal = std::mem::take(&mut adjacency.reciprocal);
        let host_of = std::mem::take(&mut adjacency.host_of);

        let mut stats = LldpResolutionStats::default();
        // Every far end no strategy could place, kept so the summary below can name them.
        //
        // `host_not_found` on its own says only how many there were, and it is the one counter
        // that does not move between scans: an unresolvable row keeps `neighbor_interface_id`
        // NULL, so the filter re-selects it every pass and the count is a standing population
        // rather than a per-run delta. A reporter seeing the same figure twice cannot tell a
        // stable set of genuinely-unknown neighbours (endpoints, phones, unmanaged gear — the
        // expected case) from a resolution defect without knowing *which* devices they are
        // (GH #668).
        let mut warnings: Vec<DiscoveryWarning> = Vec::new();
        let mut reopened = 0usize;
        let mut rebound = 0usize;

        for mut interface in std::mem::take(&mut adjacency.interfaces) {
            // What the row held on the way in. The tiers below may downgrade a binding and then
            // re-resolve it to the same value, and only a comparison against the *original* can
            // tell that apart from a change worth writing.
            let original_neighbor = interface.base.neighbor.clone();

            // A row that already names a port is re-examined rather than resolved: it is not a
            // link that failed, it is one that may have been placed on a MAC the far end repeats
            // across every port, which looks authoritative and is not.
            if let Some(Neighbor::Interface(bound_id)) = interface.base.neighbor {
                match self
                    .re_examine_port_binding(&interface, bound_id, &reciprocal, &resolver)
                    .await?
                {
                    PortBinding::Stands => continue,
                    PortBinding::Rebind(paired) => {
                        rebound += 1;
                        interface.base.neighbor = Some(Neighbor::Interface(paired));
                        self.interface_service
                            .update(&mut interface, AuthenticatedEntity::System)
                            .await?;
                        continue;
                    }
                    // Downgraded to the far-end device, which was never in doubt, and then run
                    // through the tiers below in this same pass so a tier that *can* name a port
                    // gets its turn immediately rather than a scan later.
                    PortBinding::Reopen(remote_host_id) => {
                        reopened += 1;
                        interface.base.neighbor = Some(Neighbor::Host(remote_host_id));
                    }
                }
            }

            // Rows admitted only because they already carry a resolved neighbour — an FDB-matched
            // port, say — have no protocol identity to run the tiers against. Persist a downgrade
            // if one just happened and move on.
            //
            // The one predicate, so this guard cannot throw back a row the filter above admitted
            // *for* its identity, nor keep one the tiers below have no arm for. It used to test
            // three columns by hand, one of them (`cdp_address`) that no tier reads.
            if !interface.base.has_resolvable_identity() {
                self.persist_neighbor(&mut interface, &original_neighbor)
                    .await?;
                continue;
            }

            stats.total += 1;

            // A previous pass may already have identified the remote host but not the port. Keep
            // that result and retry only the port, so a partial can never regress to nothing.
            let known_host_id = match interface.base.neighbor {
                Some(Neighbor::Host(host_id)) => Some(host_id),
                _ => None,
            };

            // Only chassis_id and port_id are used for neighbor resolution — they represent
            // actual physical connections. lldp_mgmt_addr / cdp_address are where you manage the
            // device, not necessarily the physical connection point.
            let resolved_neighbor = if let Some(chassis_id) = interface.base.resolvable_chassis_id()
            {
                let host = match known_host_id {
                    Some(host_id) => IdentityResolution::Resolved(host_id),
                    // Already run once while building the adjacency — reusing the verdict is what
                    // keeps this pass at the same query cost it had before the extra tier.
                    None => host_of
                        .get(&interface.id)
                        .copied()
                        .unwrap_or(IdentityResolution::NoStrategy),
                };
                if let Some(reason) = UnresolvedReason::from_resolution(host) {
                    warnings.extend(unmatched_neighbour_warning(
                        &interface,
                        chassis_id.identifier(),
                        interface.base.lldp_sys_name.clone(),
                        reason,
                    ));
                }
                match stats.record_host(host) {
                    None => None,
                    Some(host_id) => {
                        let port = match interface.base.lldp_port_id {
                            Some(ref port_id) => {
                                port_id.resolve_if_entry_id(&resolver, host_id).await
                            }
                            None => IdentityResolution::NoStrategy,
                        };
                        // Last resort: the port *description*. Distinct from the port id and
                        // sometimes the only one that matches — a D-Link DGS-1210-48 advertises
                        // the id as a bare port number but describes the port as
                        // "D-Link DGS-1210-48 Rev.GX/7.20.003 Port 9", which is byte-identical to
                        // that switch's own ifDescr (GH #668). Only consulted once the id has
                        // failed, so a device whose id resolves is unaffected, and scoped to the
                        // already-resolved host like every other tier.
                        let port = match port {
                            IdentityResolution::Resolved(id) => IdentityResolution::Resolved(id),
                            unresolved => {
                                match desc_worth_matching(interface.base.lldp_port_desc.as_deref())
                                {
                                    Some(desc) => {
                                        match resolver.find_if_entry_by_name(desc, host_id).await {
                                            Some(id) => IdentityResolution::Resolved(id),
                                            // Keep the port id's own verdict rather than
                                            // overwriting it: `NoStrategy` and `NotFound` are
                                            // counted separately and mean different things to
                                            // whoever reads the stats.
                                            None => unresolved,
                                        }
                                    }
                                    None => unresolved,
                                }
                            }
                        };
                        let port =
                            match Self::pair_reciprocally(port, interface.id, host_id, &reciprocal)
                            {
                                Some(paired) => {
                                    stats.ports_resolved_reciprocal += 1;
                                    paired
                                }
                                None => port,
                            };
                        if let Some(reason) = UnresolvedReason::from_resolution(port) {
                            warnings.push(unresolved_port_warning(
                                &interface,
                                host_id,
                                interface
                                    .base
                                    .lldp_port_id
                                    .as_ref()
                                    .map(|p| format!("{p:?}")),
                                reason,
                            ));
                        }
                        Some(stats.record_port(port, host_id))
                    }
                }
            } else if let Some(device_id) = interface.base.resolvable_cdp_device_id() {
                // CDP device_id is typically sysName, resolve against sys_name field
                let host = match known_host_id {
                    Some(host_id) => IdentityResolution::Resolved(host_id),
                    None => host_of
                        .get(&interface.id)
                        .copied()
                        .unwrap_or(IdentityResolution::NoStrategy),
                };
                if let Some(reason) = UnresolvedReason::from_resolution(host) {
                    warnings.extend(unmatched_neighbour_warning(
                        &interface,
                        device_id.to_string(),
                        None,
                        reason,
                    ));
                }
                match stats.record_host(host) {
                    None => None,
                    Some(host_id) => {
                        // CDP port ids are the long ifDescr form
                        let port = match interface.base.cdp_port_id {
                            Some(ref port_id) => IdentityResolution::found(
                                resolver.find_if_entry_by_name(port_id, host_id).await,
                            ),
                            None => IdentityResolution::NoStrategy,
                        };
                        let port =
                            match Self::pair_reciprocally(port, interface.id, host_id, &reciprocal)
                            {
                                Some(paired) => {
                                    stats.ports_resolved_reciprocal += 1;
                                    paired
                                }
                                None => port,
                            };
                        if let Some(reason) = UnresolvedReason::from_resolution(port) {
                            warnings.push(unresolved_port_warning(
                                &interface,
                                host_id,
                                interface
                                    .base
                                    .cdp_port_id
                                    .as_ref()
                                    .map(|id| format!("CdpPortId({id:?})")),
                                reason,
                            ));
                        }
                        Some(stats.record_port(port, host_id))
                    }
                }
            } else {
                // Unreachable: the guard above and the two arms here read the same predicate, so a
                // row that got this far has an arm. Kept as the place a future divergence lands,
                // and made loud rather than silent — a row that is counted but never judged is
                // exactly how the last three of these went unnoticed.
                stats.ladder_divergences += 1;
                tracing::warn!(
                    interface_id = %interface.id,
                    "interface passed the resolvable-identity guard but matched no resolution \
                     arm; the guard and the ladder have diverged"
                );
                None
            };

            // Persist the resolved neighbor. `None` leaves the row as it was: an existing partial
            // is preserved, and an unresolved row stays eligible for the next pass.
            if let Some(neighbor) = resolved_neighbor {
                interface.base.neighbor = Some(neighbor);
            }
            self.persist_neighbor(&mut interface, &original_neighbor)
                .await?;
        }

        tracing::info!(
            network_id = %network_id,
            total = stats.total,
            hosts_resolved = stats.hosts_resolved,
            ports_resolved = stats.ports_resolved,
            ports_resolved_reciprocal = stats.ports_resolved_reciprocal,
            // The five per-reason failure counters this line used to carry are now exactly the
            // count of their `DiscoveryWarning`s, and two sources for one number can only
            // disagree. What is left is not a failure counter at all: it reads zero unless the
            // guard and the ladder have come apart, and a non-zero here is a defect in this
            // module rather than anything about the network. See its doc for the two sites.
            ladder_divergences = stats.ladder_divergences,
            reopened,
            rebound,
            "LLDP/CDP link resolution complete"
        );

        Ok(LldpResolutionOutcome { stats, warnings })
    }

    /// Put a resolution pass's findings on the scan record they belong to.
    ///
    /// Thin by design — the decision of *where* these belong lives in
    /// [`DiscoveryService::append_historical_warnings`]; this only names the session.
    pub async fn append_resolution_warnings(
        &self,
        session_id: Uuid,
        warnings: Vec<DiscoveryWarning>,
    ) -> Result<()> {
        self.discovery_service
            .append_historical_warnings(session_id, warnings)
            .await
    }

    /// Write `interface` back only when its neighbor actually changed.
    async fn persist_neighbor(
        &self,
        interface: &mut Interface,
        original: &Option<Neighbor>,
    ) -> Result<()> {
        if &interface.base.neighbor == original {
            return Ok(());
        }
        self.interface_service
            .update(interface, AuthenticatedEntity::System)
            .await?;
        Ok(())
    }

    /// Resolve FDB (bridge forwarding database) single-MAC ports to neighbor links.
    /// Called after resolve_lldp_links — only processes ports without LLDP/CDP data
    /// that have exactly one learned MAC address (direct physical connection).
    pub async fn resolve_fdb_links(&self, network_id: Uuid) -> Result<u32> {
        let resolver = LldpResolverImpl::new(
            self.interface_service.clone(),
            self.ip_address_service.clone(),
            self.storage.clone(),
        );

        let filter = StorableFilter::<Interface>::new_for_unresolved_fdb_in_network(network_id);
        let unresolved = self.interface_service.get_all(filter).await?;

        let mut resolved_count: u32 = 0;

        for mut interface in unresolved {
            let mac = match &interface.base.fdb_macs {
                Some(macs) if macs.len() == 1 => &macs[0],
                _ => continue,
            };

            // Try to find host by MAC. A MAC on more than one device names none of them, so an
            // ambiguous verdict leaves the row unresolved rather than picking a side.
            let IdentityResolution::Resolved(host_id) =
                resolver.find_host_by_mac(mac, network_id).await
            else {
                continue;
            };

            // Try full resolution (specific port). A far end that repeats one MAC across its ports
            // names no single port, so the link stays at device level rather than being attached to
            // whichever port the database returned first.
            let neighbor = match resolver.find_if_entry_by_mac(mac, host_id).await {
                IdentityResolution::Resolved(interface_id) => Neighbor::Interface(interface_id),
                _ => Neighbor::Host(host_id),
            };

            interface.base.neighbor = Some(neighbor);
            self.interface_service
                .update(&mut interface, AuthenticatedEntity::System)
                .await?;
            resolved_count += 1;
        }

        if resolved_count > 0 {
            tracing::debug!(
                network_id = %network_id,
                resolved = resolved_count,
                "FDB link resolution complete"
            );
        }

        Ok(resolved_count)
    }
}

/// The port description, if it is worth trying as a name — the input to the last-resort tier
/// above, named so it can be tested without a resolver behind it.
///
/// Empty is nothing to match on. The `usable_identifier` half is GH #88 arriving at the tier that
/// accidentally rescued the SR Linux row: a description is worth *storing* whatever it holds, and
/// it is shown to operators, but a control character in it makes it no more a port name than it
/// made the port id one. `lldp_port_desc` cannot carry U+FFFD — it is strictly decoded and
/// NUL-stripped on the SNMP path where it is collected (gNMI and lldpd are not, so a NUL-padded description simply fails the exact-match lookup) — so control characters are the whole of what this catches.
///
/// Filtered at the lookup rather than at the write on purpose. The stored value is untouched and
/// the caller's verdict stays `unresolved`, so the row is still counted and still warned about; it
/// only stops the last tier claiming a match on a value that is not a name.
fn desc_worth_matching(desc: Option<&str>) -> Option<&str> {
    desc.filter(|d| !d.trim().is_empty() && crate::server::lldp::usable_identifier(d))
}

#[cfg(test)]
mod desc_tier_tests {
    use super::desc_worth_matching;

    #[test]
    fn a_real_description_is_still_offered_to_the_last_tier() {
        // GH #668's D-Link description, byte-identical to that switch's own ifDescr, which is the
        // whole reason this tier exists.
        assert_eq!(
            desc_worth_matching(Some("D-Link DGS-1210-48 Rev.GX/7.20.003 Port 9")),
            Some("D-Link DGS-1210-48 Rev.GX/7.20.003 Port 9")
        );
        assert_eq!(desc_worth_matching(Some("Anschluß 4")), Some("Anschluß 4"));
    }

    #[test]
    fn a_description_that_is_not_a_name_is_not_offered() {
        assert_eq!(desc_worth_matching(Some("swp\u{1}2")), None);
        assert_eq!(desc_worth_matching(Some("swp\n2")), None);
        assert_eq!(desc_worth_matching(Some("   ")), None);
        assert_eq!(desc_worth_matching(None), None);
    }
}
