//! IP/MAC-based host matching, locking, upsert, and consolidation.
use super::*;

impl HostService {
    /// Find an existing host that matches based on IP-address data (subnet+IP or MAC address).
    ///
    /// This assembles the candidate set; the decision itself lives in `select_matching_host`,
    /// which is pure and carries the matching rules (including the VRRP/CARP/HSRP handling)
    /// plus their unit tests.
    ///
    /// Returns the matched host together with its **full, unfiltered** live IP rows —
    /// discovery derives `previous_subnets` from them for subnet↔VLAN reconciliation, so
    /// loopback and virtual-router rows must stay in.
    pub(crate) async fn find_matching_host_by_ip_addresses(
        &self,
        network_id: &Uuid,
        incoming_ip_addresses: &[IPAddress],
    ) -> Result<Option<(Host, Vec<IPAddress>)>> {
        if incoming_ip_addresses.is_empty() {
            return Ok(None);
        }

        // SCD2: only match against live rows. Closed historical copies
        // (set when a snapshot fires) must not influence reconciliation.
        let filter = StorableFilter::<Host>::new_from_network_ids(&[*network_id]).live();
        let mut all_hosts = self.get_all(filter).await?;

        if all_hosts.is_empty() {
            return Ok(None);
        }

        // Oldest-first, with an id tiebreak: storage orders by `created_at ASC` only, and
        // every host created in one daemon batch shares the batch's scan_time, so without
        // the tiebreak "first match wins" would be resolved arbitrarily by the database.
        all_hosts.sort_by_key(|h| (h.created_at, h.id));

        let host_ids: Vec<Uuid> = all_hosts.iter().map(|h| h.id).collect();
        let mut ip_addresses_by_host = self
            .ip_address_service
            .get_for_hosts(&host_ids, None)
            .await?;

        let candidates: Vec<(Uuid, Vec<IPAddress>)> = all_hosts
            .iter()
            .map(|h| (h.id, ip_addresses_by_host.remove(&h.id).unwrap_or_default()))
            .collect();

        let Some(matched_id) = select_matching_host(incoming_ip_addresses, &candidates) else {
            return Ok(None);
        };

        let host_ip_addresses = candidates
            .into_iter()
            .find(|(id, _)| *id == matched_id)
            .map(|(_, ip_addresses)| ip_addresses)
            .unwrap_or_default();

        Ok(all_hosts
            .into_iter()
            .find(|h| h.id == matched_id)
            .map(|host| {
                tracing::debug!(
                    existing_host_id = %host.id,
                    existing_host_name = %host.base.name,
                    "Matched incoming IP addresses to existing host"
                );
                (host, host_ip_addresses)
            }))
    }

    /// Merge new discovery data with existing host
    pub(crate) async fn upsert_host(
        &self,
        mut existing_host: Host,
        new_host_data: Host,
        authentication: AuthenticatedEntity,
    ) -> Result<Host> {
        let host_before_updates = existing_host.clone();
        let mut has_updates = false;

        // SCD2 semantics: every successful natural-key match advances
        // last_seen_at to the scan time, regardless of whether other fields
        // change. The incoming `new_host_data` was pre-stamped by
        // `discover_host` (see `ScanContext`) so all entities from one
        // submission share one timestamp; without ScanContext the value is
        // whatever the caller put on the entity (likely a per-entity
        // Utc::now()).
        existing_host.last_seen_at = new_host_data.last_seen_at;

        tracing::trace!(
            "Upserting new host data {:?} to host {:?}",
            new_host_data,
            existing_host
        );

        // The hostname is a current observation, not a first write. A device answering to a
        // different name than it did last scan — a rebuilt machine on a re-used address, a
        // renamed DNS record — has to record the name it answers to *now*. The display name is
        // re-derived from this field a few lines below, so a hostname frozen at creation froze
        // the name with it, and the host went on wearing a label belonging to another device
        // (GH #89). A name written once and never corrected is worse than no name: it looks
        // like an answer.
        //
        // But "the current observation" is only well defined once the field has an owner. Two
        // submissions arrive for one host in every cycle: the sweep's, whose hostname is reverse
        // DNS falling back to mDNS, and a controller's, whose hostname is the name a client
        // advertised to DHCP. Let both rewrite and, wherever the two strings differ — an FQDN
        // against a short name, the ordinary shape of DHCP-to-DNS registration — they overwrite
        // each other twice a cycle for ever, taking the display name and a topology rebuild with
        // them. So a hostname the sender read off the host itself owns the field, and one it
        // heard second-hand fills it only while it is empty.
        //
        // Two residuals, both known and neither fixed here. First: a host only a controller ever
        // witnesses keeps the first hostname the controller reported, because nothing here can
        // tell that from the flapping case without provenance on the stored value. Its *name*
        // still refreshes — a controller's alias enters a rung higher. Second, and the reason
        // this rule settles the controller case but not every case: the flag separates a direct
        // observation from a second-hand one, and it cannot separate two *direct* observations of
        // one host that disagree. `network/scan.rs` does the reverse lookup per address and
        // submits one payload per address, so a host with two scanned addresses on one MAC —
        // `sw1.lan` and `sw1-mgmt.lan` — sends two authoritative hostnames per cycle and they
        // take turns, exactly as the two paths used to; two daemons with different resolvers are
        // the same shape. Every flip is a `trigger_stale` update, so the cost is a topology
        // rebuild per cycle. Choosing between two equally-authoritative PTRs needs a tiebreak
        // nobody has designed yet, and it is tracked separately.
        //
        // An absent or blank incoming hostname is not evidence of absence — a scan that could
        // not resolve one says nothing about the name, and must never clear what an earlier scan
        // learned. Stored trimmed, because it is compared, displayed, and re-derived into the
        // display name, and `" nas.lan "` is the same observation as `nas.lan`.
        if let Some(hostname) = new_host_data
            .base
            .hostname
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
        {
            let stored = existing_host.base.hostname.as_deref();
            let owns_the_field = new_host_data.base.hostname_authoritative
                || stored.is_none_or(|h| h.trim().is_empty());
            if owns_the_field && stored != Some(hostname) {
                has_updates = true;
                existing_host.base.hostname = Some(hostname.to_string());
            }
        }

        // The display name. Both candidates go through the same ladder, which is the whole
        // reason this is two arms rather than a string-shape guess: the incoming name carries
        // the rank of whatever produced it, so a controller's name refreshes on every sync, a
        // reverse-DNS hostname fills in only over something weaker, and a name a person typed is
        // never touched by either. A daemon too old to send a rank enters as `Unspecified` and
        // changes nothing on its own — the hostname arm still reproduces its old IP-upgrade.
        //
        // The second arm runs last on purpose: at equal rank it restores the name from the
        // hostname the arm above just settled, so whoever owns that field owns the label derived
        // from it. That means the two arms can each report a change and still leave the name
        // exactly as it was — a controller client offering its DHCP name at the `Hostname` rung,
        // overruled by the stored reverse-DNS one. Only the net effect is an update: counting
        // each arm separately published an `Updated` event every cycle for a name nobody changed.
        let name_before = existing_host.base.name.clone();
        existing_host
            .base
            .apply_name(new_host_data.base.name.clone());
        if let Some(hostname) = existing_host.base.hostname.clone() {
            existing_host.base.apply_name(HostName::Hostname(hostname));
        }
        if existing_host.base.name != name_before {
            has_updates = true;
        }

        // Update SNMP fields if not set
        if existing_host.base.sys_descr.is_none() && new_host_data.base.sys_descr.is_some() {
            has_updates = true;
            existing_host.base.sys_descr = new_host_data.base.sys_descr;
        }
        if existing_host.base.sys_object_id.is_none() && new_host_data.base.sys_object_id.is_some()
        {
            has_updates = true;
            existing_host.base.sys_object_id = new_host_data.base.sys_object_id;
        }
        if existing_host.base.sys_location.is_none() && new_host_data.base.sys_location.is_some() {
            has_updates = true;
            existing_host.base.sys_location = new_host_data.base.sys_location;
        }
        if existing_host.base.sys_contact.is_none() && new_host_data.base.sys_contact.is_some() {
            has_updates = true;
            existing_host.base.sys_contact = new_host_data.base.sys_contact;
        }
        if existing_host.base.management_url.is_none()
            && new_host_data.base.management_url.is_some()
        {
            has_updates = true;
            existing_host.base.management_url = new_host_data.base.management_url;
        }
        if existing_host.base.chassis_id.is_none() && new_host_data.base.chassis_id.is_some() {
            has_updates = true;
            existing_host.base.chassis_id = new_host_data.base.chassis_id;
        }
        if existing_host.base.sys_name.is_none() && new_host_data.base.sys_name.is_some() {
            has_updates = true;
            existing_host.base.sys_name = new_host_data.base.sys_name;
        }
        if existing_host.base.manufacturer.is_none() && new_host_data.base.manufacturer.is_some() {
            has_updates = true;
            existing_host.base.manufacturer = new_host_data.base.manufacturer;
        }
        if existing_host.base.model.is_none() && new_host_data.base.model.is_some() {
            has_updates = true;
            existing_host.base.model = new_host_data.base.model;
        }
        if existing_host.base.serial_number.is_none() && new_host_data.base.serial_number.is_some()
        {
            has_updates = true;
            existing_host.base.serial_number = new_host_data.base.serial_number;
        }

        // EntitySource merge: previously concatenated discovery metadata vecs
        // here. With the metadata field removed, source is just the variant
        // discriminant — propagate the new value if it's Discovery, else keep
        // existing. Discovery context is now tracked via FK columns
        // (last_discovery_id / first_discovery_id) populated post-terminal.
        existing_host.base.source = match (existing_host.base.source, new_host_data.base.source) {
            (EntitySource::Discovery, EntitySource::Discovery) => EntitySource::Discovery,
            (_, EntitySource::Discovery) => {
                has_updates = true;
                EntitySource::Discovery
            }
            (existing_source, _) => existing_source,
        };

        // Always write — even when no field changes, last_seen_at was
        // advanced above and must persist. The Updated event is only
        // published when there's a substantive field change, so consumers
        // that listen for "real" updates aren't woken by every refresh.
        self.storage().update(&mut existing_host).await?;

        if has_updates {
            let trigger_stale = existing_host.triggers_staleness(Some(host_before_updates));

            if let Some(scope) = EntityScope::from_ids(
                existing_host.id(),
                existing_host.clone().into(),
                self.get_network_id(&existing_host),
                self.get_organization_id(&existing_host),
            ) {
                self.event_bus()
                    .publish(
                        Event::new(scope, EntityOperation::Updated, authentication).with_flags(
                            EntityEventFlags {
                                trigger_stale,
                                ..Default::default()
                            },
                        ),
                    )
                    .await?;
            }
        } else {
            tracing::debug!(
                "No new data to upsert from host {} to {} (last_seen_at refresh only)",
                new_host_data.base.name,
                existing_host.base.name
            );
        }

        Ok(existing_host)
    }

    pub async fn consolidate_hosts(
        &self,
        destination_host: Host,
        other_host: Host,
        authentication: AuthenticatedEntity,
    ) -> Result<HostResponse> {
        if destination_host.id == other_host.id {
            return Err(ValidationError::new("Can't consolidate a host with itself").into());
        }

        let daemon_filter = StorableFilter::<Daemon>::new_from_host_ids(&[other_host.id]);

        if self.daemon_service.exists(daemon_filter).await? {
            return Err(ValidationError::new(
                "Can't consolidate a host that has a daemon associated with it. \
                 Consolidate the other host into the host with the daemon instead.",
            )
            .into());
        }

        // Lock BOTH hosts (in canonical order via session_lock_many): a
        // concurrent update/delete of either host must not interleave with
        // the merge. `delete_host_inner` below runs under these guards.
        let lock_guards = self
            .storage()
            .session_lock_many(
                &[
                    LockKey::Host(destination_host.id),
                    LockKey::Host(other_host.id),
                ],
                CONSOLIDATE_LOCK_TIMEOUT,
            )
            .await?;

        tracing::trace!(
            "Consolidating host {:?} into host {:?}",
            other_host,
            destination_host
        );

        // Get ip_addresses and ports for both hosts
        let dest_interfaces = self
            .ip_address_service
            .get_for_host(&destination_host.id)
            .await?;
        let other_interfaces = self.ip_address_service.get_for_host(&other_host.id).await?;

        let dest_ports = self.port_service.get_for_host(&destination_host.id).await?;
        let other_ports = self.port_service.get_for_host(&other_host.id).await?;

        // Build interface ID mapping: source interface ID -> dest interface ID
        // Transfer non-conflicting ip_addresses to destination

        // Count MACs per host to detect VLAN sub-interfaces. MAC-based conflict detection
        // is only safe when both sides have a unique MAC (count == 1). If either host has
        // multiple ip_addresses sharing a MAC (VLANs/bridges/bonds), MAC matching would
        // incorrectly collapse distinct sub-interfaces during the merge.
        let dest_mac_counts: HashMap<MacAddress, usize> = dest_interfaces
            .iter()
            .filter_map(|i| i.base.mac_address)
            .fold(HashMap::new(), |mut acc, mac| {
                *acc.entry(mac).or_insert(0) += 1;
                acc
            });
        let other_mac_counts: HashMap<MacAddress, usize> = other_interfaces
            .iter()
            .filter_map(|i| i.base.mac_address)
            .fold(HashMap::new(), |mut acc, mac| {
                *acc.entry(mac).or_insert(0) += 1;
                acc
            });

        let mut interface_id_map: HashMap<Uuid, Uuid> = HashMap::new();
        for other_iface in &other_interfaces {
            // Check for conflict: same (subnet_id + ip_address) or same MAC (when 1:1)
            let matching_dest_iface = dest_interfaces.iter().find(|dest_iface| {
                // Match by subnet + IP (always safe — same logical ip_address)
                (dest_iface.base.subnet_id == other_iface.base.subnet_id
                    && dest_iface.base.ip_address == other_iface.base.ip_address)
                    // Match by MAC only when both hosts have a single interface with this MAC.
                    // Multiple ip_addresses sharing a MAC = VLAN sub-interfaces that should
                    // be preserved separately, not collapsed during merge.
                    || (dest_iface.base.mac_address.is_some()
                        && dest_iface.base.mac_address == other_iface.base.mac_address
                        && dest_iface
                            .base
                            .mac_address
                            .map(|mac| {
                                dest_mac_counts.get(&mac).copied().unwrap_or(0) == 1
                                    && other_mac_counts.get(&mac).copied().unwrap_or(0) == 1
                            })
                            .unwrap_or(false))
            });

            if let Some(dest_iface) = matching_dest_iface {
                // Conflict: map source ID to destination ID
                tracing::debug!(
                    source_interface_id = %other_iface.id,
                    dest_interface_id = %dest_iface.id,
                    ip = %other_iface.base.ip_address,
                    "IP address conflict - mapping to existing destination ip_address"
                );
                interface_id_map.insert(other_iface.id, dest_iface.id);
            } else {
                // No conflict: transfer interface to destination host
                let mut transferred = other_iface.clone();
                transferred.base.host_id = destination_host.id;
                self.ip_address_service
                    .update(&mut transferred, authentication.clone())
                    .await?;
                tracing::debug!(
                    ip_address_id = %other_iface.id,
                    ip = %other_iface.base.ip_address,
                    "Transferred ip_address to destination host"
                );
                // Map to itself (ID unchanged, just host_id changed)
                interface_id_map.insert(other_iface.id, other_iface.id);
            }
        }

        // Build port ID mapping: source_port_id -> dest_port_id
        // Transfer non-conflicting ports to destination
        let mut port_id_map: HashMap<Uuid, Uuid> = HashMap::new();
        for other_port in &other_ports {
            let other_config = other_port.base.port_type.config();

            // Check for conflict: same (number + protocol)
            let matching_dest_port = dest_ports.iter().find(|dest_port| {
                let dest_config = dest_port.base.port_type.config();
                dest_config.number == other_config.number
                    && dest_config.protocol == other_config.protocol
            });

            if let Some(dest_port) = matching_dest_port {
                // Conflict: map source ID to destination ID
                tracing::debug!(
                    source_port_id = %other_port.id,
                    dest_port_id = %dest_port.id,
                    port = %other_config.number,
                    "Port conflict - mapping to existing destination port"
                );
                port_id_map.insert(other_port.id, dest_port.id);
            } else {
                // No conflict: transfer port to destination host
                let mut transferred =
                    other_port.with_host(destination_host.id, destination_host.base.network_id);
                self.port_service
                    .update(&mut transferred, authentication.clone())
                    .await?;
                tracing::debug!(
                    port_id = %other_port.id,
                    port = %other_config.number,
                    "Transferred port to destination host"
                );
                // Map to itself (ID unchanged, just host_id changed)
                port_id_map.insert(other_port.id, other_port.id);
            }
        }

        // Upsert host data (metadata merge).
        //
        // Neither side is making a fresh observation here: both hostnames came back out of the
        // database, and a stored row cannot say where its own came from. `Host::from_row` reports
        // every row as directly observed, which is true of the row being merged *into* — whatever
        // is in that column has already won the field — and says nothing at all about a row used
        // as the merge *source*. Passed through unqualified, a hostname the network only ever
        // heard second-hand (a controller repeating a DHCP name) overwrites one a scan resolved
        // off the destination host itself. A merge is not an observation, so the source may fill
        // an empty hostname and nothing more (GH #89).
        let mut merge_source = other_host.clone();
        merge_source.base.hostname_authoritative = false;
        let updated_host = self
            .upsert_host(
                destination_host.clone(),
                merge_source,
                authentication.clone(),
            )
            .await?;

        // Get services for both hosts. SCD2: live rows only.
        let destination_services = self
            .service_service
            .get_all(StorableFilter::<Service>::new_from_host_ids(&[destination_host.id]).live())
            .await?;

        let other_services = self
            .service_service
            .get_all(StorableFilter::<Service>::new_from_host_ids(&[other_host.id]).live())
            .await?;

        // Transfer services, updating binding IDs using the maps
        for mut service in other_services {
            // Check for duplicate by name + service_definition
            let is_duplicate = destination_services.iter().any(|dest_svc| {
                dest_svc.base.name == service.base.name
                    && dest_svc.base.service_definition.id() == service.base.service_definition.id()
            });

            if is_duplicate {
                tracing::debug!(
                    service_name = %service.base.name,
                    service_def = %service.base.service_definition.id(),
                    "Skipping duplicate service during consolidation"
                );
                continue;
            }

            // Update host_id
            service.base.host_id = updated_host.id;
            service.base.network_id = updated_host.base.network_id;

            // Remap binding IDs using our maps
            for binding in &mut service.base.bindings {
                match &mut binding.base.binding_type {
                    BindingType::IPAddress { ip_address_id } => {
                        if let Some(&new_id) = interface_id_map.get(ip_address_id) {
                            *ip_address_id = new_id;
                        } else {
                            tracing::warn!(
                                service = %service.base.name,
                                ip_address_id = %ip_address_id,
                                "IP address not found in mapping during consolidation"
                            );
                        }
                    }
                    BindingType::Port {
                        port_id,
                        ip_address_id,
                    } => {
                        if let Some(&new_port_id) = port_id_map.get(port_id) {
                            *port_id = new_port_id;
                        } else {
                            tracing::warn!(
                                service = %service.base.name,
                                port_id = %port_id,
                                "Port not found in mapping during consolidation"
                            );
                        }
                        if let Some(iface_id) = ip_address_id {
                            if let Some(&new_iface_id) = interface_id_map.get(iface_id) {
                                *ip_address_id = Some(new_iface_id);
                            } else {
                                tracing::warn!(
                                    service = %service.base.name,
                                    ip_address_id = %iface_id,
                                    "IP address not found in mapping, falling back to all-ip_addresses"
                                );
                                *ip_address_id = None;
                            }
                        }
                    }
                }
            }

            self.service_service
                .update(&mut service, authentication.clone())
                .await
                .map_err(|e| {
                    tracing::error!(
                        service_id = %service.id,
                        service_name = %service.base.name,
                        "Failed to update service during consolidation: {}",
                        e
                    );
                    anyhow!(
                        "Failed to update service '{}' during consolidation: {}",
                        service.base.name,
                        e
                    )
                })?;
        }

        // Migrate credential assignments from other host to destination host
        let other_assignments = self
            .credential_service
            .get_credential_assignments_for_host(&other_host.id)
            .await?;

        if !other_assignments.is_empty() {
            use crate::server::credentials::r#impl::types::CredentialAssignment;

            let dest_assignments = self
                .credential_service
                .get_credential_assignments_for_host(&updated_host.id)
                .await?;

            let dest_cred_map: HashMap<Uuid, &CredentialAssignment> = dest_assignments
                .iter()
                .map(|a| (a.credential_id, a))
                .collect();

            let mut merged: Vec<CredentialAssignment> = dest_assignments.clone();
            let mut migrated_count = 0usize;

            for other in &other_assignments {
                // Remap ip_address_ids if present
                let remapped_iface_ids = match &other.ip_address_ids {
                    None => None,
                    Some(ids) => {
                        let remapped: Vec<Uuid> = ids
                            .iter()
                            .filter_map(|id| interface_id_map.get(id).copied())
                            .collect();
                        if remapped.is_empty() {
                            // All ip_addresses were dropped — skip this assignment
                            continue;
                        }
                        Some(remapped)
                    }
                };

                if let Some(dest_assignment) = dest_cred_map.get(&other.credential_id) {
                    // Both hosts have this credential — merge with broadest-scope-wins
                    let merged_iface_ids =
                        match (&dest_assignment.ip_address_ids, &remapped_iface_ids) {
                            (None, _) | (_, None) => None, // Either is all-interfaces → all
                            (Some(dest_ids), Some(other_ids)) => {
                                let mut union = dest_ids.clone();
                                for id in other_ids {
                                    if !union.contains(id) {
                                        union.push(*id);
                                    }
                                }
                                Some(union)
                            }
                        };

                    // Update the existing dest entry in merged list
                    if let Some(entry) = merged
                        .iter_mut()
                        .find(|a| a.credential_id == other.credential_id)
                    {
                        entry.ip_address_ids = merged_iface_ids;
                    }
                } else {
                    // Only on other host — add to merged list
                    merged.push(CredentialAssignment {
                        credential_id: other.credential_id,
                        ip_address_ids: remapped_iface_ids,
                    });
                }
                migrated_count += 1;
            }

            self.credential_service
                .set_host_credentials(&updated_host.id, &merged)
                .await?;

            tracing::info!(
                migrated = migrated_count,
                source_host_id = %other_host.id,
                dest_host_id = %updated_host.id,
                "Migrated credential assignments during consolidation"
            );
        }

        // Delete other host (remaining children that weren't transferred will
        // cascade). Inner variant: this task already holds Host(other_host.id).
        self.delete_host_inner(&other_host.id, authentication)
            .await?;

        tracing::info!(
            source_host_id = %other_host.id,
            source_host_name = %other_host.base.name,
            dest_host_id = %updated_host.id,
            dest_host_name = %updated_host.base.name,
            ip_addresses_mapped = %interface_id_map.len(),
            ports_mapped = %port_id_map.len(),
            "Hosts consolidated"
        );

        crate::server::shared::storage::lock::release_all(lock_guards).await?;

        // Return response with hydrated children
        let (ip_addresses, ports, services, interfaces) =
            self.load_children_for_host(&updated_host.id).await?;
        Ok(HostResponse::from_host_with_children(
            updated_host,
            ip_addresses,
            ports,
            services,
            interfaces,
        ))
    }
}
