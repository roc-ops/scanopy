//! Inbound daemon message processing: status, startup, registration, capabilities, discovery entities, and migration.
use super::*;
use crate::server::interfaces::r#impl::base::InterfaceDataComplete;

impl DaemonService {
    // ========================================================================
    // Processing methods
    // ========================================================================

    /// Process a heartbeat from a daemon.
    /// Also resolves interfaced subnets and updates capabilities.
    pub async fn process_status(
        &self,
        daemon_id: Uuid,
        status: DaemonStatus,
        auth: AuthenticatedEntity,
    ) -> Result<(), ApiError> {
        let mut daemon = self
            .get_by_id(&daemon_id)
            .await?
            .ok_or_else(|| ApiError::entity_not_found::<Daemon>(daemon_id))?;

        daemon.base.last_seen = Some(Utc::now());
        // NOTE: We intentionally do NOT update URL from status.
        // URL is only set:
        // - ServerPoll: Admin provides URL during provisioning
        // - DaemonPoll: URL not needed (server never connects to daemon)
        // This prevents daemons from overwriting admin-configured URLs.
        // Name/mode: for a provisioned daemon (api_key_id set) these are authoritative
        // server-side and must not be overwritten by the daemon's reported values.
        if daemon.base.api_key_id.is_none() {
            daemon.base.name = status.name;
            daemon.base.mode = status.mode;
        }

        // Update version if provided (for ServerPoll mode status responses)
        if let Some(version) = status.version {
            daemon.base.version = Some(version);
        }

        // Resolve interfaced subnets and persist them to the
        // `daemon_interfaced_subnets` junction (replaces the old capabilities JSONB).
        //   • v0.15.0+ daemons send full `Subnet` objects; create-or-match by CIDR
        //     yields canonical, FK-valid ids.
        //   • Pre-0.15 daemons send bare ids in the legacy `capabilities` blob; keep
        //     honoring them so those daemons still report interfaced subnets, but
        //     existence-filter first — a dangling id can't satisfy the FK (that
        //     referential-integrity gap is exactly what this table fixes).
        let subnet_ids: Vec<Uuid> = if supports_unified_discovery(daemon.base.version.as_ref()) {
            let mut resolved_ids = Vec::new();
            for subnet in status.interfaced_subnets {
                match self.subnet_service.create(subnet, auth.clone()).await {
                    Ok(resolved) => resolved_ids.push(resolved.id),
                    Err(e) => {
                        tracing::warn!(error = ?e, "Failed to resolve interfaced subnet");
                    }
                }
            }
            resolved_ids
        } else {
            self.filter_existing_subnet_ids(&status.capabilities.interfaced_subnet_ids)
                .await
        };

        self.interfaced_subnet_storage
            .save_interfaced_subnets_for_daemon(&daemon_id, &subnet_ids)
            .await
            .map_err(|e| {
                ApiError::internal_error(&format!("Failed to save interfaced subnets: {e}"))
            })?;

        self.update(&mut daemon, auth).await?;
        Ok(())
    }

    /// Keep only the subnet ids that currently exist as live `subnets` rows, so a
    /// legacy daemon's stale/dangling id can't violate the junction FK. Goes through
    /// `SubnetService` (not storage) to respect entity boundaries.
    async fn filter_existing_subnet_ids(&self, ids: &[Uuid]) -> Vec<Uuid> {
        if ids.is_empty() {
            return Vec::new();
        }
        let filter = StorableFilter::<Subnet>::new_from_uuids_column("id", ids).live();
        match self.subnet_service.get_all(filter).await {
            Ok(subnets) => {
                let existing: std::collections::HashSet<Uuid> =
                    subnets.into_iter().map(|s| s.id).collect();
                ids.iter()
                    .copied()
                    .filter(|id| existing.contains(id))
                    .collect()
            }
            Err(e) => {
                tracing::warn!(error = ?e, "Failed to validate legacy interfaced subnet ids; skipping");
                Vec::new()
            }
        }
    }

    /// Process a daemon startup announcement
    pub async fn process_startup(
        &self,
        daemon_id: Uuid,
        version: Version,
        auth: AuthenticatedEntity,
    ) -> Result<ServerCapabilities, ApiError> {
        // Reject daemons below the minimum supported version
        let policy = DaemonVersionPolicy::default();
        if version < policy.minimum_supported {
            return Err(ApiError::daemon_version_too_old(
                &version.to_string(),
                &policy.minimum_supported.to_string(),
            ));
        }

        let mut daemon = self
            .get_by_id(&daemon_id)
            .await?
            .ok_or_else(|| ApiError::entity_not_found::<Daemon>(daemon_id))?;

        let was_pre_unified = !supports_unified_discovery(daemon.base.version.as_ref());

        daemon.base.version = Some(version.clone());
        daemon.base.last_seen = Some(Utc::now());

        // A daemon that just booted and reached /startup is by definition active
        // again. Clear standby and grant a bounded grace period — the nightly
        // inactivity check skips daemons within the grace window, letting
        // scheduled discoveries fire and refresh `last_finished` before
        // inactivity is re-evaluated.
        if daemon.base.standby {
            daemon.base.standby = false;
            daemon.base.standby_cleared_at = Some(Utc::now());
            tracing::info!(
                daemon_id = %daemon_id,
                "Cleared daemon standby on restart ({}-day grace granted)",
                STANDBY_GRACE_PERIOD_DAYS
            );
        }

        self.update(&mut daemon, auth).await?;

        tracing::info!(daemon_id = %daemon_id, version = %version, "Daemon startup");

        // Migrate legacy discoveries if daemon just upgraded to unified-capable version
        if was_pre_unified
            && supports_unified_discovery(Some(&version))
            && let Err(e) = self
                .migrate_discoveries_to_unified(
                    daemon_id,
                    daemon.base.host_id,
                    daemon.base.network_id,
                )
                .await
        {
            tracing::warn!(
                daemon_id = %daemon_id,
                error = ?e,
                "Failed to migrate legacy discoveries to unified"
            );
        }

        // If daemon has no non-historical discoveries, create defaults
        // (e.g. daemon reconnecting after discoveries were deleted)
        let filter = StorableFilter::new_from_uuid_column("daemon_id", &daemon_id).live_configs();
        let existing_discoveries = self.discovery_service.get_all(filter).await?;
        if existing_discoveries.is_empty() {
            let network = self
                .network_service
                .get_by_id(&daemon.base.network_id)
                .await?
                .ok_or_else(|| ApiError::entity_not_found::<Network>(daemon.base.network_id))?;
            let organization = self
                .organization_service
                .get_by_id(&network.base.organization_id)
                .await?
                .ok_or_else(|| {
                    ApiError::entity_not_found::<
                        crate::server::organizations::r#impl::base::Organization,
                    >(network.base.organization_id)
                })?;
            let is_free_plan = organization.base.plan.map(|p| p.is_free()).unwrap_or(true);
            // Reconnect safety-net (discoveries were deleted): no registration request is in
            // scope on startup, so we can't recover the init-command targeting here. Recreate
            // with empty targeting; the daemon re-registering restores its integration_targets.
            self.create_default_discovery_jobs(
                daemon_id,
                daemon.base.network_id,
                daemon.base.host_id,
                is_free_plan,
                &[],
            )
            .await?;
        }

        let status = policy.evaluate(Some(&version));

        Ok(ServerCapabilities {
            server_version: policy.latest.clone(),
            minimum_daemon_version: policy.minimum_supported.clone(),
            deprecation_warnings: status.warnings,
        })
    }

    /// Process a daemon registration request
    pub async fn process_registration(
        &self,
        request: DaemonRegistrationRequest,
        auth: AuthenticatedEntity,
    ) -> Result<DaemonRegistrationResponse, ApiError> {
        let host_service = self
            .host_service
            .get()
            .ok_or_else(|| ApiError::internal_error("HostService not initialized"))?;

        // Resolve the network from the authenticated key rather than trusting the
        // request body. A provisioned DaemonPoll daemon starts without a network_id
        // and sends nil; the server derives it from the 1:1 key. For a legacy
        // shared-key daemon the key's network equals request.network_id, so this is
        // a no-op there (and it stops a daemon claiming a network its key can't reach).
        let effective_network_id = auth
            .network_ids()
            .first()
            .copied()
            .unwrap_or(request.network_id);

        // Check if this is a demo organization - block daemon registration
        let network = self
            .network_service
            .get_by_id(&effective_network_id)
            .await?
            .ok_or_else(|| ApiError::entity_not_found::<Network>(effective_network_id))?;

        let org_id = network.base.organization_id;
        let organization =
            self.organization_service
                .get_by_id(&org_id)
                .await?
                .ok_or_else(|| {
                    ApiError::entity_not_found::<
                        crate::server::organizations::r#impl::base::Organization,
                    >(org_id)
                })?;
        let plan = organization
            .base
            .plan
            .unwrap_or_else(crate::server::billing::plans::get_free_plan);

        if plan.is_demo() {
            return Err(ApiError::demo_mode_blocked());
        }

        tracing::info!("{:?}", request);

        // For a 1:1 provisioned key the auth layer resolved the daemon from the key,
        // so that is the authoritative id — the client-sent request.daemon_id is
        // untrusted and, for a freshly provisioned daemon, not yet known. For a legacy
        // shared-key daemon, auth resolves to the header id, which equals
        // request.daemon_id, so this is a no-op there.
        let effective_daemon_id = auth.daemon_id().unwrap_or(request.daemon_id);

        // Parse version early for use in server_capabilities
        let daemon_version = request
            .version
            .as_ref()
            .and_then(|v| semver::Version::parse(v).ok());

        // Reject daemons below the minimum supported version
        let policy = DaemonVersionPolicy::default();
        if daemon_version
            .as_ref()
            .is_some_and(|v| v < &policy.minimum_supported)
        {
            return Err(ApiError::daemon_version_too_old(
                &daemon_version.unwrap().to_string(),
                &policy.minimum_supported.to_string(),
            ));
        }

        // Compute server_capabilities if version was provided
        let server_capabilities = daemon_version.as_ref().map(|v| {
            let status = policy.evaluate(Some(v));
            ServerCapabilities {
                server_version: policy.latest.clone(),
                minimum_daemon_version: policy.minimum_supported.clone(),
                deprecation_warnings: status.warnings,
            }
        });

        // Check if daemon already exists (re-registration scenario)
        if let Some(mut existing_daemon) = self.get_by_id(&effective_daemon_id).await? {
            tracing::info!(
                daemon_id = %effective_daemon_id,
                host_id = %existing_daemon.base.host_id,
                "Daemon already registered, updating registration"
            );

            // Update daemon with current info
            // NOTE: We do NOT update URL from registration request.
            // URL is only set via admin provisioning for ServerPoll daemons.
            // (Interfaced subnets are not taken from registration — they flow via the
            // status heartbeat / update-capabilities channels into the junction.)
            existing_daemon.base.last_seen = Some(Utc::now());
            // For a provisioned daemon the server-side name and mode are authoritative
            // (chosen at provision, bound to the 1:1 key). A silent install defaulting to
            // "scanopy-daemon" must not clobber the provisioned name. A provisioned record
            // has api_key_id set; a legacy self-registered daemon does not, and keeps
            // reporting its own name/mode.
            if existing_daemon.base.api_key_id.is_none() {
                existing_daemon.base.mode = request.mode;
                existing_daemon.base.name = request.name;
            }
            // A daemon that's re-registering is by definition no longer on standby.
            existing_daemon.base.standby = false;
            let was_pre_unified =
                !supports_unified_discovery(existing_daemon.base.version.as_ref());
            if let Some(v) = daemon_version.clone() {
                existing_daemon.base.version = Some(v);
            }

            let updated_daemon = self.update(&mut existing_daemon, auth).await?;

            // A provisioned daemon's FIRST contact lands here (its record already exists from
            // provisioning), not in the new-registration branch — so emit the onboarding
            // milestone here too, or the org never records FirstDaemonRegistered and the UI
            // keeps showing "install a daemon" while discovery actually runs. Idempotent: the
            // emit is guarded by org.not_onboarded, so restarts don't re-fire it.
            self.emit_first_daemon_telemetry(updated_daemon.id, updated_daemon.base.network_id)
                .await?;

            // Migrate legacy discoveries if daemon just upgraded to unified-capable version
            if was_pre_unified
                && supports_unified_discovery(existing_daemon.base.version.as_ref())
                && let Err(e) = self
                    .migrate_discoveries_to_unified(
                        existing_daemon.id,
                        existing_daemon.base.host_id,
                        existing_daemon.base.network_id,
                    )
                    .await
            {
                tracing::warn!(
                    daemon_id = %existing_daemon.id,
                    error = ?e,
                    "Failed to migrate legacy discoveries to unified"
                );
            }

            return Ok(DaemonRegistrationResponse {
                daemon: updated_daemon,
                host_id: existing_daemon.base.host_id,
                server_capabilities,
            });
        }

        // Records are created ONLY through provisioning for modern daemons. A daemon
        // that supports server-provisioned identity (>= 0.17.5) is installed against a
        // pre-provisioned record bound to a 1:1 key; if its register doesn't resolve to
        // an existing record, something is wrong (unprovisioned, or a key that doesn't
        // match the daemon) — creating a second record here is the bug testers hit on
        // re-install. Reject instead. Self-registration below is a back-compat path for
        // legacy (< 0.17.5) daemons that join with a shared network key.
        if supports_server_provisioned_identity(daemon_version.as_ref()) {
            // Coded (not bad_request) so the daemon can recognize this as a terminal
            // registration rejection and stop retrying it as if the server were unreachable.
            return Err(ApiError::daemon_not_provisioned());
        }

        // Check daemon limit for unverified orgs (allows 1st daemon)
        self.check_unverified_daemon_limit(org_id).await?;

        // New registration - create host and daemon
        let mut dummy_host = Host::new(HostBase {
            network_id: effective_network_id,
            // Placeholder identity: the daemon's own reported name, which sits at the same rung
            // as a hostname, so a later scan of the machine can improve on it.
            name: HostName::default(),
            hostname: None,
            hostname_authoritative: true,
            description: None,
            source: EntitySource::Discovery,
            virtualization_metadata: None,
            virtualization_service_id: None,
            hidden: false,
            tags: Vec::new(),
            sys_descr: None,
            sys_object_id: None,
            sys_location: None,
            sys_contact: None,
            management_url: None,
            chassis_id: None,
            sys_name: None,
            manufacturer: None,
            model: None,
            serial_number: None,
            credential_assignments: vec![],
        });
        dummy_host
            .base
            .apply_name(HostName::Hostname(request.name.clone()));

        let host_response = host_service
            .discover_host(
                dummy_host,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                // No interfaces in this registration stub; nothing to prune, and no neighbour
                // data to preserve against.
                true,
                InterfaceDataComplete::default(),
                None,
                auth.clone(),
                None,
            )
            .await?;

        // Seed the daemon host's loopback so a daemon-host socket/proxy credential is probed on the
        // very first scan (the credential mapping is snapshotted before the daemon self-reports).
        if let Err(e) = host_service
            .seed_loopback(host_response.id, effective_network_id, auth.clone())
            .await
        {
            tracing::warn!(host_id = %host_response.id, error = %e, "Failed to seed daemon host loopback");
        }

        // Version gate (mirrors the discovery-update handler): reject any registration
        // target whose credential type is too new for this daemon's version, before
        // it's applied to the host_credentials junction or the Discovery row.
        for target in &request.integration_targets {
            if let Some(cred) = self
                .credential_service
                .get_by_id(&target.credential_id())
                .await?
            {
                let disc = CredentialTypeDiscriminants::from(&cred.base.credential_type);
                if !disc.compatible_with_daemon(daemon_version.as_ref()) {
                    return Err(ApiError::bad_request(&format!(
                        "Credential type \"{}\" requires daemon version {} or newer, but this daemon is on {}.",
                        disc.display_name(),
                        disc.minimum_daemon_version(),
                        daemon_version
                            .as_ref()
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "an unknown version".to_string()),
                    )));
                }
            }
        }

        // Init-command targeting is persisted on the daemon's Discovery row, never assigned to a
        // host here. Every target — daemon-host sockets included — earns its assignment by
        // probing successfully during discovery, at which point it's assigned to the host it
        // worked on.
        // If user_id is nil (old daemon), fall back to org owner
        let user_id = if request.user_id.is_nil() {
            self.user_service
                .get_organization_owners(&org_id)
                .await?
                .first()
                .map(|u| u.id)
                .unwrap_or(request.user_id)
        } else {
            request.user_id
        };

        let mut daemon = Daemon::new(DaemonBase {
            host_id: host_response.id,
            network_id: effective_network_id,
            // DaemonPoll mode: URL not needed (server never connects to daemon)
            // ServerPoll mode: URL is set during provisioning, not during registration
            url: String::new(),
            last_seen: Some(Utc::now()),
            mode: request.mode,
            name: request.name,
            tags: Vec::new(),
            version: daemon_version,
            user_id,
            api_key_id: None,
            is_unreachable: false,
            standby: false,
            standby_cleared_at: None,
        });

        daemon.id = effective_daemon_id;

        let registered_daemon = self.create(daemon, auth.clone()).await?;

        // Send telemetry event if this is the organization's first daemon
        self.emit_first_daemon_telemetry(registered_daemon.id, registered_daemon.base.network_id)
            .await?;

        // Create default discovery jobs
        let is_free_plan = plan.is_free();
        self.create_default_discovery_jobs(
            effective_daemon_id,
            effective_network_id,
            host_response.id,
            is_free_plan,
            &request.integration_targets,
        )
        .await?;

        Ok(DaemonRegistrationResponse {
            daemon: registered_daemon,
            host_id: host_response.id,
            server_capabilities,
        })
    }

    /// Process a capabilities update from a daemon
    /// Legacy `POST /{id}/update-capabilities` channel: a pre-0.15 daemon reporting
    /// its interfaced subnets as bare ids. Route them into the junction
    /// (existence-filtered), consistent with the heartbeat's legacy branch, so these
    /// daemons keep reporting. Modern daemons use the status `Vec<Subnet>` channel.
    pub async fn process_capabilities(
        &self,
        daemon_id: Uuid,
        capabilities: LegacyCapabilities,
        _auth: AuthenticatedEntity,
    ) -> Result<(), ApiError> {
        tracing::debug!(
            daemon_id = %daemon_id,
            interfaced_subnet_ids = ?capabilities.interfaced_subnet_ids,
            "Updating daemon interfaced subnets (legacy capabilities channel)",
        );

        // Confirm the daemon exists (auth already scoped it to the caller's network).
        if self.get_by_id(&daemon_id).await?.is_none() {
            return Err(ApiError::entity_not_found::<Daemon>(daemon_id));
        }

        let subnet_ids = self
            .filter_existing_subnet_ids(&capabilities.interfaced_subnet_ids)
            .await;
        self.interfaced_subnet_storage
            .save_interfaced_subnets_for_daemon(&daemon_id, &subnet_ids)
            .await
            .map_err(|e| {
                ApiError::internal_error(&format!("Failed to save interfaced subnets: {e}"))
            })?;
        Ok(())
    }

    /// Process a discovery progress update
    pub async fn process_discovery_progress(
        &self,
        update: DiscoveryUpdatePayload,
    ) -> Result<(), ApiError> {
        self.discovery_service.update_session(update).await?;
        Ok(())
    }

    /// Process discovered entities from a daemon.
    ///
    /// This function processes entities with best-effort semantics: if one entity fails,
    /// we continue processing the rest and return confirmations for successfully processed
    /// entities. This is critical for ServerPoll mode where the daemon is waiting for
    /// confirmations - failing the entire batch due to one bad entity would cause the
    /// daemon to timeout and stall.
    pub async fn process_discovery_entities(
        &self,
        entities: BufferedEntities,
        auth: AuthenticatedEntity,
    ) -> Result<CreatedEntitiesPayload, ApiError> {
        let host_service = self
            .host_service
            .get()
            .ok_or_else(|| ApiError::internal_error("HostService not initialized"))?;

        // Compute host limit context from the first host's network → org → plan
        let limit_ctx = if let Some(first_host) = entities.hosts.first() {
            let network_id = first_host.host.base.network_id;
            if let Ok(Some(network)) = self.network_service.get_by_id(&network_id).await {
                let org_id = network.base.organization_id;
                let plan = self
                    .organization_service
                    .get_by_id(&org_id)
                    .await?
                    .and_then(|o| o.base.plan)
                    .unwrap_or_else(crate::server::billing::plans::get_free_plan);
                if let Some(limit) = plan.host_limit() {
                    let org_networks = self
                        .network_service
                        .get_all(StorableFilter::<Network>::new_from_org_id(&org_id))
                        .await
                        .unwrap_or_default();
                    let org_network_ids: Vec<Uuid> = org_networks.iter().map(|n| n.id).collect();
                    Some(HostLimitContext {
                        limit,
                        org_id,
                        org_network_ids,
                        plan,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let mut created_hosts = Vec::new();
        let mut created_subnets = Vec::new();
        let mut host_failures = 0;
        let mut subnet_failures = 0;
        let mut limit_event_emitted = false;
        let mut billing_limit_reached: Option<(u64, Uuid)> = None;
        let mut first_host_error: Option<String> = None;

        // One ScanContext per batch — every host's children share the same
        // scan_time so per-scan diff queries see consistent timestamps
        // across the entire daemon submission. See ScanContext for rationale.
        let scan_ctx = auth
            .daemon_id()
            .map(crate::server::shared::services::scan_context::ScanContext::new);

        // Process each discovered host - continue on failure to avoid blocking entire batch
        for host_request in entities.hosts {
            let pending_id = host_request.host.id;
            let host_name = host_request.host.base.name.clone();
            match host_service
                .discover_host(
                    host_request.host,
                    host_request.ip_addresses,
                    host_request.ports,
                    host_request.services,
                    host_request.interfaces,
                    host_request.subnets,
                    host_request.interfaces_complete,
                    host_request.interface_data_complete,
                    scan_ctx.as_ref(),
                    auth.clone(),
                    limit_ctx.as_ref(),
                )
                .await
            {
                Ok(host_response) => {
                    // Credential assignments are persisted inside discover_host()
                    // after remapping daemon interface UUIDs to server-assigned UUIDs.
                    // (Loopback credential scoping is handled at registration via
                    // seed_loopback + explicit integration_targets IP overrides; the
                    // old target_ips-based scoping was removed with target_ips.)
                    created_hosts.push((pending_id, host_response));
                }
                Err(e) => {
                    host_failures += 1;

                    // Retain the first failure so the synchronous single-host
                    // discovery handler can surface the real cause (multi-host
                    // batches still continue past it).
                    if first_host_error.is_none() {
                        first_host_error = Some(e.to_string());
                    }

                    // Emit billing event once when host limit is hit
                    if !limit_event_emitted
                        && e.to_string().contains("Host limit reached")
                        && let Some(ctx) = &limit_ctx
                    {
                        limit_event_emitted = true;
                        billing_limit_reached = Some((ctx.limit, ctx.org_id));
                        let _ = self
                            .event_bus
                            .publish(Event::new(
                                OrgScope {
                                    organization_id: ctx.org_id,
                                },
                                BillingOperation::FeatureLimitHit {
                                    limit_type: LimitType::Hosts,
                                    current_count: ctx.limit,
                                    limit: ctx.limit,
                                    plan: ctx.plan,
                                    source: LimitSource::Discovery,
                                },
                                auth.clone(),
                            ))
                            .await;
                    }

                    tracing::warn!(
                        pending_id = %pending_id,
                        host_name = %host_name,
                        error = %e,
                        "Failed to process discovered host - skipping (daemon will retry or timeout)"
                    );
                }
            }
        }

        // Emit FirstHostDiscovered telemetry if this is the org's first discovered host
        if !created_hosts.is_empty()
            && let Some((_, first_host)) = created_hosts.first()
            && let Ok(Some(network)) = self.network_service.get_by_id(&first_host.network_id).await
            && let Ok(Some(org)) = self
                .organization_service
                .get_by_id(&network.base.organization_id)
                .await
            && org.not_onboarded(&OnboardingOperationDiscriminants::FirstHostDiscovered)
        {
            let _ = self
                .event_bus
                .publish(Event::new(
                    OrgScope {
                        organization_id: org.id,
                    },
                    OnboardingOperation::FirstHostDiscovered,
                    AuthenticatedEntity::System,
                ))
                .await;
        }

        // Process discovered subnets - continue on failure to avoid blocking entire batch
        for subnet in entities.subnets {
            let pending_id = subnet.id;
            let cidr = subnet.base.cidr;
            match self.subnet_service.create(subnet, auth.clone()).await {
                Ok(actual_subnet) => {
                    created_subnets.push((pending_id, actual_subnet));
                }
                Err(e) => {
                    subnet_failures += 1;
                    tracing::warn!(
                        pending_id = %pending_id,
                        cidr = %cidr,
                        error = %e,
                        "Failed to process discovered subnet - skipping (daemon will retry or timeout)"
                    );
                }
            }
        }

        if host_failures > 0 || subnet_failures > 0 {
            tracing::info!(
                hosts_created = created_hosts.len(),
                hosts_failed = host_failures,
                subnets_created = created_subnets.len(),
                subnets_failed = subnet_failures,
                "Entity processing completed with some failures"
            );
        }

        Ok(CreatedEntitiesPayload {
            subnets: created_subnets,
            hosts: created_hosts,
            billing_limit_hit: billing_limit_reached,
            first_host_error,
        })
    }

    /// Get pending discovery work for a daemon.
    /// When work is returned, the session is immediately transitioned to Starting phase
    /// to prevent it from being dispatched again on subsequent poll cycles.
    /// Returns None if there's already an active session running on the daemon.
    pub async fn get_pending_work(&self, daemon_id: Uuid) -> Option<DiscoveryUpdatePayload> {
        // Don't dispatch new work if there's already an active session
        if self
            .discovery_service
            .has_active_session_for_daemon(&daemon_id)
            .await
        {
            return None;
        }

        // Lazily start the daemon's initial discovery run the first time it pulls work.
        // Provisioning creates the Discovery CONFIG but no session (so a not-yet-installed
        // daemon's discovery can't be swept as a stalled Pending session). This is the one
        // choke point both DaemonPoll (/request-work) and ServerPoll (poll loop) funnel
        // through, and it only runs once the daemon is ready_for_work — so the initial
        // session is born and dispatched in the same work-pull, never left idle-Pending.
        // Idempotent: start_session stamps `last_run`, so a discovery that has ever run is
        // skipped here and governed by its schedule/adhoc semantics thereafter.
        self.start_initial_discovery_sessions(daemon_id).await;

        let sessions = self
            .discovery_service
            .get_sessions_for_daemon(&daemon_id)
            .await;

        if let Some(work) = sessions.first().cloned() {
            // Transition to Starting so this won't be returned again
            self.discovery_service
                .transition_session_to_starting(work.session_id)
                .await;
            Some(work)
        } else {
            None
        }
    }

    /// Start the initial session for any of the daemon's live discoveries that have
    /// never run. Called on the first work-pull (see get_pending_work). A discovery's
    /// `last_run` is stamped by start_session, so this fires exactly once per discovery
    /// — the initial run — after which the schedule (or one-shot adhoc) takes over.
    /// Infallible on purpose (get_pending_work has no error channel): failures are logged.
    async fn start_initial_discovery_sessions(&self, daemon_id: Uuid) {
        let filter = StorableFilter::new_from_uuid_column("daemon_id", &daemon_id).live_configs();
        let discoveries = match self.discovery_service.get_all(filter).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(daemon_id = %daemon_id, error = ?e, "Failed to load discoveries for initial-session start");
                return;
            }
        };

        for discovery in discoveries {
            if !discovery.base.run_type.never_ran() {
                continue;
            }
            if let Err(e) = self
                .discovery_service
                .start_session(discovery, AuthenticatedEntity::System)
                .await
            {
                // A concurrent poll may have already started it (start_session enforces
                // one active session per discovery) — benign; log at debug.
                tracing::debug!(daemon_id = %daemon_id, error = ?e, "Initial discovery session not started (likely already running)");
            }
        }
    }

    /// Get pending cancellation request for a daemon
    pub async fn get_pending_cancellation(&self, daemon_id: Uuid) -> Option<Uuid> {
        let (has_cancellation, session_id) = self
            .discovery_service
            .pull_cancellation_for_daemon(&daemon_id)
            .await;
        if has_cancellation {
            Some(session_id)
        } else {
            None
        }
    }

    /// Create default discovery jobs for a newly contacted daemon
    pub async fn create_default_discovery_jobs(
        &self,
        daemon_id: Uuid,
        network_id: Uuid,
        host_id: Uuid,
        is_free_plan: bool,
        integration_targets: &[IntegrationTarget],
    ) -> Result<(), ApiError> {
        // Idempotency guard: a daemon gets exactly one set of default discovery
        // jobs. This is now called from provision (where seed refs are known),
        // legacy self-registration, and ServerPoll first-contact — so without this
        // guard a provisioned daemon that later registers / is first-contacted
        // would get a duplicate discovery. Skip if any live discovery exists.
        let existing = self
            .discovery_service
            .get_all(StorableFilter::new_from_uuid_column("daemon_id", &daemon_id).live_configs())
            .await?;
        if !existing.is_empty() {
            tracing::info!(
                daemon_id = %daemon_id,
                "Daemon already has discoveries; skipping default discovery creation"
            );
            return Ok(());
        }

        tracing::info!(
            daemon_id = %daemon_id,
            network_id = %network_id,
            host_id = %host_id,
            is_free_plan,
            "Creating default discovery jobs for daemon"
        );

        // Free plans use AdHoc (run once immediately), paid plans use Scheduled
        let default_run_type = if is_free_plan {
            RunType::AdHoc { last_run: None }
        } else {
            RunType::Scheduled {
                cron_schedule: WEEKLY_SUNDAY_MIDNIGHT_CRON.to_string(),
                last_run: None,
                enabled: true,
                timezone: None,
            }
        };

        // Create a single Unified discovery combining self-report, network, and docker
        let unified_discovery_type = DiscoveryType::Unified {
            host_id,
            subnet_ids: None,
            host_naming_fallback: HostNamingFallback::BestService,
            scan_settings: ScanSettings::default(),
        };

        let mut discovery = Discovery::new(DiscoveryBase {
            run_type: default_run_type,
            discovery_type: unified_discovery_type.clone(),
            name: "Discovery".to_string(),
            daemon_id,
            network_id,
            tags: Vec::new(),
        });
        // Persist the init-command targeting on the daemon's own Discovery so it's present
        // before the first session dispatches (the #637 fix: per-daemon, not on the credential).
        discovery.integration_targets = integration_targets.to_vec();

        // Create the Discovery CONFIG only — do NOT start a session here. The initial
        // session is started lazily the first time the daemon pulls work (see
        // get_pending_work). This is what keeps a provisioned-but-not-yet-installed
        // daemon's discovery from being created as a `Pending` session and then
        // cancelled by the 5-minute stall sweeper before the daemon ever connects.
        self.discovery_service
            .create_discovery(discovery, AuthenticatedEntity::System)
            .await?;

        Ok(())
    }

    /// Migrate legacy discoveries (SelfReport/Network/Docker) to a single Unified discovery.
    /// Archives old discoveries as Historical and creates a new Unified discovery inheriting
    /// settings from the primary Network discovery (if any).
    pub async fn migrate_discoveries_to_unified(
        &self,
        daemon_id: Uuid,
        host_id: Uuid,
        network_id: Uuid,
    ) -> Result<(), ApiError> {
        let filter = StorableFilter::new_from_uuid_column("daemon_id", &daemon_id).live_configs();
        let discoveries = self.discovery_service.get_all(filter).await?;

        // Skip if any are already Unified
        if discoveries
            .iter()
            .any(|d| matches!(d.base.discovery_type, DiscoveryType::Unified { .. }))
        {
            return Ok(());
        }

        // Skip if there are no discoveries to migrate
        if discoveries.is_empty() {
            return Ok(());
        }

        // Select primary: prefer Network discovery that is enabled + scheduled + most recently updated
        let primary = discoveries
            .iter()
            .filter(|d| {
                matches!(d.base.discovery_type, DiscoveryType::Network { .. })
                    && d.base.run_type.is_scheduled_enabled()
            })
            .max_by_key(|d| d.updated_at)
            .or_else(|| discoveries.iter().max_by_key(|d| d.updated_at));

        let primary = match primary {
            Some(p) => p,
            None => return Ok(()),
        };

        // Extract settings from primary
        let (subnet_ids, host_naming_fallback) = match &primary.base.discovery_type {
            DiscoveryType::Network {
                subnet_ids,
                host_naming_fallback,
                ..
            } => (subnet_ids.clone(), *host_naming_fallback),
            _ => (None, HostNamingFallback::BestService),
        };

        // Create unified discovery inheriting run_type and tags from primary
        let unified_type = DiscoveryType::Unified {
            host_id,
            subnet_ids,
            host_naming_fallback,
            scan_settings: ScanSettings::default(),
        };

        self.discovery_service
            .create_discovery(
                Discovery::new(DiscoveryBase {
                    run_type: primary.base.run_type.clone(),
                    discovery_type: unified_type.clone(),
                    name: "Discovery".to_string(),
                    daemon_id,
                    network_id,
                    tags: primary.base.tags.clone(),
                }),
                AuthenticatedEntity::System,
            )
            .await?;

        // Delete old discoveries
        let count = discoveries.len();
        for old in &discoveries {
            if let Err(e) = self
                .discovery_service
                .delete(&old.id, AuthenticatedEntity::System)
                .await
            {
                tracing::warn!(
                    discovery_id = %old.id,
                    error = ?e,
                    "Failed to delete legacy discovery during migration"
                );
            }
        }

        tracing::info!(
            daemon_id = %daemon_id,
            count = count,
            "Migrated {} legacy discoveries to unified for daemon {}",
            count,
            daemon_id
        );

        Ok(())
    }

    /// Emit FirstDaemonRegistered telemetry event if this is the org's first daemon
    pub async fn emit_first_daemon_telemetry(
        &self,
        daemon_id: Uuid,
        network_id: Uuid,
    ) -> Result<(), ApiError> {
        let network = self
            .network_service
            .get_by_id(&network_id)
            .await?
            .ok_or_else(|| ApiError::entity_not_found::<Network>(network_id))?;

        let org = self
            .organization_service
            .get_by_id(&network.base.organization_id)
            .await?
            .ok_or_else(|| ApiError::not_found("Organization not found".to_string()))?;

        if org.not_onboarded(&OnboardingOperationDiscriminants::FirstDaemonRegistered) {
            let daemon_name = self
                .get_by_id(&daemon_id)
                .await?
                .map(|d| d.base.name.clone())
                .unwrap_or_else(|| "your daemon".to_string());

            tracing::info!(
                daemon_id = %daemon_id,
                organization_id = %org.id,
                "Emitting FirstDaemonRegistered telemetry on first contact"
            );

            self.event_bus
                .publish(Event::new(
                    OrgScope {
                        organization_id: org.id,
                    },
                    OnboardingOperation::FirstDaemonRegistered {
                        daemon_name: daemon_name.to_string(),
                        network_name: network.base.name.clone(),
                    },
                    AuthenticatedEntity::System,
                ))
                .await?;
        }

        Ok(())
    }
}
