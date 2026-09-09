//! The reciprocal-LLDP pairing tier.
//!
//! Every other tier identifies a far-end port from something the far end advertised about itself,
//! which fails outright on the switch families that report one chassis MAC across every port
//! (D-Link, TP-Link/Omada, UniFi, Westermo): the identifier names the device and nothing narrower.
//! This tier identifies nothing at all. It observes that two devices name each other, and binds the
//! two *local* interfaces that did the naming — both already attached by `ifIndex` on their own
//! device, so the far-end port never has to be recognised and the shared MAC cannot get in the way.
use super::*;

impl HostService {
    /// The reciprocal-LLDP tier: bind two interfaces that name each other and nothing else.
    ///
    /// Consulted only once the port-id and port-description tiers have failed, and only for a pair
    /// where **each side has exactly one** interface pointing at the other. Both endpoints are
    /// *locally* known interfaces, attached by `ifIndex` on their own device, so the far end's port
    /// never has to be identified from what it advertises — which is what makes this work on the
    /// switch families that report one chassis MAC across every port (D-Link, TP-Link/Omada,
    /// UniFi, Westermo) where no MAC can name a port.
    ///
    /// A LAG between two switches is genuinely ambiguous and is left device-level: guessing which
    /// member is which is the same arbitrary-port outcome the shared-MAC guard exists to prevent.
    pub(super) fn pair_reciprocally(
        port: IdentityResolution,
        interface_id: Uuid,
        host_id: Uuid,
        reciprocal: &HashMap<Uuid, (Uuid, Uuid)>,
    ) -> Option<IdentityResolution> {
        if matches!(port, IdentityResolution::Resolved(_)) {
            return None;
        }
        // The pairing is only usable when it agrees with the host the ladder above settled on —
        // otherwise the two disagree about which device is at the far end, and the port id wins.
        match reciprocal.get(&interface_id) {
            Some(&(paired_id, paired_host)) if paired_host == host_id => {
                Some(IdentityResolution::Resolved(paired_id))
            }
            _ => None,
        }
    }

    /// Build the network's neighbour adjacency and the reciprocal pairs that follow from it.
    ///
    /// One query for the interfaces that name a neighbour, one batched query to find the host
    /// behind each already-bound far-end port, and the existing chassis ladder for the rows that
    /// are not resolved yet — whose verdicts are cached so the resolution pass does not repeat
    /// them.
    ///
    /// `evidence_cutoff` is the instant before which a `neighbor_seen_at` counts as stale — the
    /// network's own staleness window, so a link is judged by the same rule and the same setting
    /// as every other freshness verdict.
    pub(super) async fn build_neighbor_adjacency(
        &self,
        network_id: Uuid,
        resolver: &LldpResolverImpl,
        evidence_cutoff: DateTime<Utc>,
    ) -> Result<NeighborAdjacency> {
        let filter = StorableFilter::<Interface>::new_for_lldp_neighbors_in_network(network_id);
        let interfaces = self.interface_service.get_all(filter).await?;

        // The host behind every already-bound far-end port, in one query rather than one each.
        let bound_ids: Vec<Uuid> = interfaces
            .iter()
            .filter_map(|i| match i.base.neighbor {
                Some(Neighbor::Interface(id)) => Some(id),
                _ => None,
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let mut host_of_interface: HashMap<Uuid, Uuid> = HashMap::new();
        if !bound_ids.is_empty() {
            let filter = StorableFilter::<Interface>::new_from_entity_ids(&bound_ids).live();
            for bound in self.interface_service.get_all(filter).await? {
                host_of_interface.insert(bound.id, bound.base.host_id);
            }
        }

        let mut host_of: HashMap<Uuid, IdentityResolution> = HashMap::new();
        // (local host, remote host) -> the local ports that name that remote host.
        let mut ports_between: HashMap<(Uuid, Uuid), Vec<NamingPort>> = HashMap::new();

        for interface in &interfaces {
            let resolution = match interface.base.neighbor {
                // Already placed: the stored neighbor *is* the verdict, and re-deriving it would
                // let the two disagree.
                Some(Neighbor::Interface(bound_id)) => {
                    IdentityResolution::found(host_of_interface.get(&bound_id).copied())
                }
                Some(Neighbor::Host(host_id)) => IdentityResolution::Resolved(host_id),
                // The same two arms, chosen by the same accessors, as the ladder in
                // `resolve_lldp_links` — they must pick the same arm for a row or the verdict
                // cached here is answered for one identifier and spent on another.
                None => {
                    if let Some(chassis_id) = interface.base.resolvable_chassis_id() {
                        chassis_id
                            .resolve_host_id(
                                resolver,
                                network_id,
                                interface.base.lldp_sys_name.as_deref(),
                            )
                            .await
                    } else if let Some(device_id) = interface.base.resolvable_cdp_device_id() {
                        resolver.find_host_by_sys_name(device_id, network_id).await
                    } else {
                        IdentityResolution::NoStrategy
                    }
                }
            };
            host_of.insert(interface.id, resolution);

            // Whether this row says what it says from evidence the window still carries. The
            // `Some(Neighbor::_)` arms above read the stored binding rather than the identifiers,
            // so without this a binding is its own confirmation for ever.
            //
            // `None` is unknown, not stale: a row no scan has ever had evidence for — or that
            // predates the column — must not lose its binding the moment this ships.
            let evidence_current = interface
                .base
                .neighbor_seen_at
                .is_none_or(|seen| seen >= evidence_cutoff);

            // A device naming itself contributes no adjacency and must never pair.
            if let IdentityResolution::Resolved(remote_host_id) = resolution
                && remote_host_id != interface.base.host_id
            {
                ports_between
                    .entry((interface.base.host_id, remote_host_id))
                    .or_default()
                    .push(NamingPort {
                        interface_id: interface.id,
                        evidence_current,
                    });
            }
        }

        Ok(NeighborAdjacency {
            interfaces,
            host_of,
            reciprocal: reciprocal_pairs(&ports_between),
        })
    }

    /// Whether an existing port binding still stands, and what to do if it does not.
    ///
    /// `unresolved_lldp_port_in_network` selects only rows with `neighbor_interface_id IS NULL`, so
    /// a binding made before that MAC's uniqueness was checked is never revisited: it is not a link
    /// that failed to resolve, it is one that resolved to an arbitrary port and looks authoritative.
    /// Without this, tightening the rule would only ever apply to newly-seen neighbours and every
    /// existing wrong edge would survive indefinitely.
    ///
    /// Reciprocal evidence is consulted first, and that is what keeps this from churning: a binding
    /// the pairing confirms is left untouched rather than being torn down and rebuilt on every
    /// scan, which at the customer's scale would be an SCD2 write per link per scan.
    pub(super) async fn re_examine_port_binding(
        &self,
        interface: &Interface,
        bound_id: Uuid,
        reciprocal: &HashMap<Uuid, (Uuid, Uuid)>,
        resolver: &LldpResolverImpl,
    ) -> Result<PortBinding> {
        if let Some(&(paired_id, _)) = reciprocal.get(&interface.id) {
            return Ok(if paired_id == bound_id {
                PortBinding::Stands
            } else {
                // Two locally-known interfaces naming each other beat an identifier the far end
                // advertised about itself, which is what the current binding rests on.
                PortBinding::Rebind(paired_id)
            });
        }

        // Only the tiers that match on a MAC rest on that MAC's uniqueness; a port matched on a
        // name, an ifIndex or an IP is unaffected and re-opening it would tear down a healthy link.
        if !interface.port_bound_by_mac() {
            return Ok(PortBinding::Stands);
        }

        let bound_filter = StorableFilter::<Interface>::new_from_entity_ids(&[bound_id]).live();
        let Some(bound) = self
            .interface_service
            .get_unique(bound_filter)
            .await?
            .at_most_one()?
        else {
            return Ok(PortBinding::Stands);
        };
        let Some(mac) = bound.base.mac_address else {
            return Ok(PortBinding::Stands);
        };

        // Ask the guard itself rather than re-deriving "is this MAC unique on that device", so
        // the two can never disagree about which bindings are legitimate.
        if matches!(
            resolver
                .find_if_entry_by_mac(&mac.to_string(), bound.base.host_id)
                .await,
            IdentityResolution::Ambiguous
        ) {
            Ok(PortBinding::Reopen(bound.base.host_id))
        } else {
            Ok(PortBinding::Stands)
        }
    }
}

/// A local port that names a remote host, and whether it still says so from evidence a scan
/// actually carried — as opposed to from a stored binding already pointing at the far end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NamingPort {
    interface_id: Uuid,
    evidence_current: bool,
}

/// The pairs where each device names the other on exactly one port.
///
/// The "exactly one each way" rule is the whole guard. Two switches joined by a LAG name each other
/// on several ports and there is no evidence in LLDP for which member faces which — pairing them
/// would name an arbitrary port and draw it as authoritative, the precise failure the shared-MAC
/// guard exists to prevent. Those stay device-level.
///
/// The tally counts *every* naming port, stored bindings included — that is what keeps a LAG whose
/// members have already resolved device-level, and it must not be narrowed. Only the emission is
/// gated on evidence, below.
fn reciprocal_pairs(
    ports_between: &HashMap<(Uuid, Uuid), Vec<NamingPort>>,
) -> HashMap<Uuid, (Uuid, Uuid)> {
    let mut reciprocal = HashMap::new();
    for ((local_host, remote_host), local_ports) in ports_between {
        let [local_port] = local_ports[..] else {
            continue;
        };
        let Some(remote_ports) = ports_between.get(&(*remote_host, *local_host)) else {
            continue;
        };
        let [remote_port] = remote_ports[..] else {
            continue;
        };
        // A pair is two devices *naming* each other. A stored binding read back as adjacency is
        // the binding under examination, so a pair resting on one confirms only itself — and
        // `re_examine_port_binding` would then call a link whose evidence has completely
        // disappeared confirmed, for ever. Both sides are required: the far end may well be
        // answering perfectly while it is the local port whose evidence vanished, and gating one
        // side alone would downgrade one endpoint while the other kept pointing at it.
        if !local_port.evidence_current || !remote_port.evidence_current {
            continue;
        }
        reciprocal.insert(
            local_port.interface_id,
            (remote_port.interface_id, *remote_host),
        );
    }
    reciprocal
}

/// What re-examining an existing port binding concluded.
pub(super) enum PortBinding {
    /// Leave it alone — no write.
    Stands,
    /// Reciprocal evidence names a different port on the same device.
    Rebind(Uuid),
    /// The binding rests on a MAC the far end repeats across its ports. Downgraded to the far-end
    /// device (which was never in doubt) and retried by the tiers in the same pass.
    Reopen(Uuid),
}

/// The reciprocal tier's decision rule, exercised without a database.
///
/// What is under test is which adjacency shapes are allowed to produce a port-precise link — the
/// question the shared-MAC guard turns on — not the SQL that assembles them.
#[cfg(test)]
mod reciprocal_tests {
    use super::*;

    /// A port naming a neighbour from evidence a scan actually carried.
    fn evidenced(interface_id: Uuid) -> NamingPort {
        NamingPort {
            interface_id,
            evidence_current: true,
        }
    }

    /// A port that names a neighbour only because a stored binding still points at it — the shape
    /// a link takes once its LLDP/CDP/FDB evidence has stopped arriving.
    fn unevidenced(interface_id: Uuid) -> NamingPort {
        NamingPort {
            interface_id,
            evidence_current: false,
        }
    }

    /// Two switches, one cable, each naming the other on one port. Neither can identify the
    /// other's port from what it advertises (both report one chassis MAC across every port), but
    /// both endpoints are locally known, so the pair is unambiguous.
    #[test]
    fn a_pair_that_names_each_other_once_binds_both_ways() {
        let (switch_a, switch_b) = (Uuid::new_v4(), Uuid::new_v4());
        let (port_a, port_b) = (Uuid::new_v4(), Uuid::new_v4());

        let pairs = reciprocal_pairs(&HashMap::from([
            ((switch_a, switch_b), vec![evidenced(port_a)]),
            ((switch_b, switch_a), vec![evidenced(port_b)]),
        ]));

        assert_eq!(pairs.get(&port_a), Some(&(port_b, switch_b)));
        assert_eq!(pairs.get(&port_b), Some(&(port_a, switch_a)));
    }

    /// A LAG names the same neighbour from several ports and LLDP carries nothing saying which
    /// member faces which. Guessing would draw an arbitrary port as authoritative.
    #[test]
    fn a_lag_between_two_switches_stays_device_level() {
        let (switch_a, switch_b) = (Uuid::new_v4(), Uuid::new_v4());
        let pairs = reciprocal_pairs(&HashMap::from([
            (
                (switch_a, switch_b),
                vec![evidenced(Uuid::new_v4()), evidenced(Uuid::new_v4())],
            ),
            (
                (switch_b, switch_a),
                vec![evidenced(Uuid::new_v4()), evidenced(Uuid::new_v4())],
            ),
        ]));

        assert!(pairs.is_empty());
    }

    /// One side sees two links to the other but only one comes back. The single port is still not
    /// identified — which of the two it answers is exactly what is unknown.
    #[test]
    fn an_asymmetric_count_names_no_port_on_either_side() {
        let (switch_a, switch_b) = (Uuid::new_v4(), Uuid::new_v4());

        let pairs = reciprocal_pairs(&HashMap::from([
            (
                (switch_a, switch_b),
                vec![evidenced(Uuid::new_v4()), evidenced(Uuid::new_v4())],
            ),
            ((switch_b, switch_a), vec![evidenced(Uuid::new_v4())]),
        ]));

        assert!(pairs.is_empty());
    }

    /// The failure this column exists for: a port whose neighbour evidence has stopped arriving
    /// keeps its stored binding, and `build_neighbor_adjacency` reads that binding back as
    /// adjacency. Pairing on it would make the binding its own confirmation, so
    /// `re_examine_port_binding` would answer `Stands` for a link nothing evidences any more.
    ///
    /// The far end is deliberately still answering: in the case this was reproduced from it is the
    /// local port that went quiet, and a rule that only checked the far end would confirm it.
    #[test]
    fn a_pair_resting_on_evidence_that_stopped_arriving_does_not_pair() {
        let (switch_a, switch_b) = (Uuid::new_v4(), Uuid::new_v4());
        let (port_a, port_b) = (Uuid::new_v4(), Uuid::new_v4());

        let pairs = reciprocal_pairs(&HashMap::from([
            ((switch_a, switch_b), vec![unevidenced(port_a)]),
            ((switch_b, switch_a), vec![evidenced(port_b)]),
        ]));

        assert!(pairs.is_empty());
    }

    /// A LAG whose members have already resolved names the far end from stored bindings rather
    /// than from identifiers. Those still have to count, or the tally would see one evidenced port
    /// each way, pair them, and draw an arbitrary LAG member as authoritative — the outcome the
    /// "exactly one each way" rule exists to prevent.
    #[test]
    fn a_lag_stays_device_level_when_only_one_member_still_has_evidence() {
        let (switch_a, switch_b) = (Uuid::new_v4(), Uuid::new_v4());

        let pairs = reciprocal_pairs(&HashMap::from([
            (
                (switch_a, switch_b),
                vec![evidenced(Uuid::new_v4()), unevidenced(Uuid::new_v4())],
            ),
            (
                (switch_b, switch_a),
                vec![evidenced(Uuid::new_v4()), unevidenced(Uuid::new_v4())],
            ),
        ]));

        assert!(pairs.is_empty());
    }

    /// A neighbour that never names us back — an endpoint, a phone, a device scanned by something
    /// that does not read its LLDP — carries no reciprocal evidence at all.
    #[test]
    fn a_one_sided_adjacency_does_not_pair() {
        let (switch, endpoint) = (Uuid::new_v4(), Uuid::new_v4());

        let pairs = reciprocal_pairs(&HashMap::from([(
            (switch, endpoint),
            vec![evidenced(Uuid::new_v4())],
        )]));

        assert!(pairs.is_empty());
    }

    /// A device with one link to each of two neighbours pairs both: the rule counts ports *per
    /// neighbour pair*, not per device, or a switch with more than one uplink would never pair.
    #[test]
    fn one_port_per_neighbour_pairs_every_neighbour() {
        let (core, edge_one, edge_two) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let (core_to_one, core_to_two) = (Uuid::new_v4(), Uuid::new_v4());
        let (one_to_core, two_to_core) = (Uuid::new_v4(), Uuid::new_v4());

        let pairs = reciprocal_pairs(&HashMap::from([
            ((core, edge_one), vec![evidenced(core_to_one)]),
            ((edge_one, core), vec![evidenced(one_to_core)]),
            ((core, edge_two), vec![evidenced(core_to_two)]),
            ((edge_two, core), vec![evidenced(two_to_core)]),
        ]));

        assert_eq!(pairs.get(&core_to_one), Some(&(one_to_core, edge_one)));
        assert_eq!(pairs.get(&core_to_two), Some(&(two_to_core, edge_two)));
    }

    /// The tier runs only once the identifiers the far end advertised have failed: a port id that
    /// named a single port is authoritative and reciprocal evidence must not displace it.
    #[test]
    fn a_port_the_advertised_id_already_named_is_left_alone() {
        let named = Uuid::new_v4();
        let local = Uuid::new_v4();
        let host = Uuid::new_v4();
        let reciprocal = HashMap::from([(local, (Uuid::new_v4(), host))]);

        assert!(
            HostService::pair_reciprocally(
                IdentityResolution::Resolved(named),
                local,
                host,
                &reciprocal,
            )
            .is_none()
        );
    }

    /// A pairing that points at a different device than the chassis ladder settled on is not
    /// evidence about this link — the two disagree about what is at the far end.
    #[test]
    fn a_pairing_disagreeing_with_the_resolved_host_is_not_used() {
        let local = Uuid::new_v4();
        let reciprocal = HashMap::from([(local, (Uuid::new_v4(), Uuid::new_v4()))]);

        assert!(
            HostService::pair_reciprocally(
                IdentityResolution::Ambiguous,
                local,
                Uuid::new_v4(),
                &reciprocal,
            )
            .is_none()
        );
    }
}
