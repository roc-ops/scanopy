//! Demo data for populating demo organizations with realistic network infrastructure.
//!
//! This module provides a complete dataset representing "Acme Technologies", a mid-size
//! company with MSP operations. The data includes multiple networks, subnets, hosts,
//! services, daemons, API keys, tags, and dependencies.

use crate::daemon::discovery::types::base::DiscoveryPhase;
use crate::server::{
    bindings::r#impl::base::Binding,
    credentials::r#impl::{
        base::{Credential, CredentialBase},
        mapping::IntegrationTarget,
        types::{CredentialAssignment, CredentialType, SecretValue},
    },
    daemon_api_keys::r#impl::base::{DaemonApiKey, DaemonApiKeyBase},
    daemons::r#impl::{
        api::DiscoveryUpdatePayload,
        base::{Daemon, DaemonBase, DaemonMode},
    },
    dependencies::r#impl::{
        base::{Dependency, DependencyBase, DependencyMembers},
        types::DependencyType,
    },
    discovery::r#impl::{
        base::{Discovery, DiscoveryBase},
        scan_settings::ScanSettings,
        types::{DiscoveryType, HostNamingFallback, RunType},
    },
    hosts::r#impl::{
        base::{Host, HostBase},
        name::HostName,
        virtualization::{HostVirtualization, ProxmoxVirtualization},
    },
    interfaces::r#impl::base::{IfAdminStatus, IfOperStatus, Interface, InterfaceBase},
    ip_addresses::r#impl::base::{IPAddress, IPAddressBase},
    lldp::{LldpChassisId, LldpPortId},
    networks::r#impl::{DEFAULT_STALE_AFTER_HOURS, Network, NetworkBase},
    ports::r#impl::base::{Port, PortType},
    services::{
        definitions::ServiceDefinitionRegistry,
        r#impl::{
            base::{Service, ServiceBase},
            virtualization::{DockerVirtualization, ServiceVirtualization},
        },
    },
    shared::{
        api_key_common::{ApiKeyType, generate_api_key_for_storage},
        types::{Color, entities::EntitySource},
    },
    shares::r#impl::base::{Share, ShareBase, ShareOptions},
    subnets::r#impl::{
        base::{Subnet, SubnetBase},
        types::SubnetType,
    },
    tags::r#impl::base::{Tag, TagBase},
    topology::types::{
        base::{Topology, TopologyBase, TopologyOptions, TopologyRequestOptions},
        edges::EdgeStyle,
        grouping::ElementRule,
    },
    user_api_keys::r#impl::base::{UserApiKey, UserApiKeyBase},
    users::r#impl::permissions::UserOrgPermissions,
    vlans::r#impl::base::{Vlan, VlanBase},
    vlans::r#impl::subnet_vlans::{SubnetVlanRecord, SubnetVlanRecordBase},
};
use chrono::{DateTime, Duration, Utc};
use cidr::{IpCidr, Ipv4Cidr};
use mac_address::MacAddress;
use secrecy::SecretString;
use semver::Version;
use std::net::{IpAddr, Ipv4Addr};
use uuid::Uuid;

// ============================================================================
// Demo Data Container
// ============================================================================

/// A host bundled with its ip_addresses, ports, and services for creation via discover_host
pub struct HostWithServices {
    pub host: Host,
    pub ip_addresses: Vec<IPAddress>,
    pub ports: Vec<Port>,
    pub services: Vec<Service>,
}

/// Deferred neighbor update to apply after all interfaces exist.
/// Uses host_name + if_index to identify entries (stable across creation)
/// instead of pre-generated UUIDs (which may not be preserved by storage).
pub struct NeighborUpdate {
    /// Source interface identifier
    pub source_host_name: String,
    pub source_if_index: i32,
    /// Target interface identifier (for Interface neighbors)
    pub target_host_name: String,
    pub target_if_index: i32,
}

/// Network-to-credential association for junction table seeding
pub struct NetworkCredentialAssignment {
    pub network_id: Uuid,
    pub credential_ids: Vec<Uuid>,
}

/// Pre-generated UUIDs for dependency wiring.
/// Service IDs for HubAndSpoke deps (service-level members),
/// binding IDs for RequestPath deps (port-level members).
struct DependencyServiceIds {
    // HubAndSpoke: service-level members
    prometheus_hq: Uuid,
    grafana_hq: Uuid,
    uptime_kuma: Uuid,
    // RequestPath: binding-level members
    traefik_hq_binding: Uuid,
    gitea_hq_binding: Uuid,
    haproxy_dc_binding: Uuid,
    app01_dc_binding: Uuid,
    mariadb_dc_binding: Uuid,
    // Backup Flow (RequestPath): binding-level members
    pve_hq1_binding: Uuid,
    truenas_binding: Uuid,
    // Observability Stack (HubAndSpoke): service-level members
    prometheus_dc: Uuid,
    grafana_dc: Uuid,
    jaeger_dc: Uuid,
    // Storage Tier (HubAndSpoke): service-level members
    minio_dc: Uuid,
    ceph_dc: Uuid,
    elasticsearch_dc: Uuid,
    // Docker daemon service IDs: shared with the DockerBridge subnets' virtualization
    docker_hq: Uuid,
    docker_dc: Uuid,
}

/// Container for all demo data entities
pub struct DemoData {
    pub tags: Vec<Tag>,
    pub credentials: Vec<Credential>,
    pub network_credential_assignments: Vec<NetworkCredentialAssignment>,
    pub networks: Vec<Network>,
    pub subnets: Vec<Subnet>,
    pub hosts_with_services: Vec<HostWithServices>,
    /// "Recently discovered" hosts created AFTER the per-network snapshot, so
    /// the snapshot captures an earlier state than the live view. See
    /// [`generate_recent_hosts`].
    pub recent_hosts_with_services: Vec<HostWithServices>,
    pub vlans: Vec<Vlan>,
    /// Subnet↔VLAN junction rows, derived from the interface `native_vlan_id`
    /// and IP↔subnet relationships (the same rule the server's discovery
    /// reconciler uses). See [`generate_subnet_vlan_records`].
    pub subnet_vlan_records: Vec<SubnetVlanRecord>,
    pub interfaces: Vec<Interface>,
    pub neighbor_updates: Vec<NeighborUpdate>,
    pub daemons: Vec<Daemon>,
    pub api_keys: Vec<DaemonApiKey>,
    pub dependencies: Vec<Dependency>,
    pub topologies: Vec<Topology>,
    pub discoveries: Vec<Discovery>,
    pub shares: Vec<Share>,
    pub user_api_keys: Vec<(UserApiKey, Vec<Uuid>)>,
}

impl DemoData {
    /// Generate all demo data for the given organization
    pub fn generate(organization_id: Uuid, user_id: Uuid) -> Self {
        let now = Utc::now();

        // Pre-generate service UUIDs used by both host/service and dependency generators
        let dep_svc_ids = DependencyServiceIds {
            prometheus_hq: Uuid::new_v4(),
            grafana_hq: Uuid::new_v4(),
            uptime_kuma: Uuid::new_v4(),
            traefik_hq_binding: Uuid::new_v4(),
            gitea_hq_binding: Uuid::new_v4(),
            haproxy_dc_binding: Uuid::new_v4(),
            app01_dc_binding: Uuid::new_v4(),
            mariadb_dc_binding: Uuid::new_v4(),
            pve_hq1_binding: Uuid::new_v4(),
            truenas_binding: Uuid::new_v4(),
            prometheus_dc: Uuid::new_v4(),
            grafana_dc: Uuid::new_v4(),
            jaeger_dc: Uuid::new_v4(),
            minio_dc: Uuid::new_v4(),
            ceph_dc: Uuid::new_v4(),
            elasticsearch_dc: Uuid::new_v4(),
            docker_hq: Uuid::new_v4(),
            docker_dc: Uuid::new_v4(),
        };

        // Generate all entities in dependency order
        let tags = generate_tags(organization_id, now);
        let credentials = generate_credentials(organization_id, now);
        let networks = generate_networks(organization_id, &tags, &credentials, now);
        let subnets = generate_subnets(
            &networks,
            &tags,
            dep_svc_ids.docker_hq,
            dep_svc_ids.docker_dc,
            now,
        );
        let network_credential_assignments =
            generate_network_credential_assignments(&networks, &credentials);
        let hosts_with_services = generate_hosts_and_services(
            &networks,
            &subnets,
            &tags,
            &credentials,
            &dep_svc_ids,
            now,
        );
        let recent_hosts_with_services = generate_recent_hosts(&networks, &subnets, now);

        // Collect hosts for daemon generation and interface generation
        let hosts: Vec<&Host> = hosts_with_services.iter().map(|h| &h.host).collect();
        let ip_addresses: Vec<&IPAddress> = hosts_with_services
            .iter()
            .flat_map(|h| h.ip_addresses.iter())
            .collect();

        let vlans = generate_vlans(&networks, organization_id, now);
        let (interfaces, neighbor_updates) =
            generate_interfaces(&networks, &hosts, &ip_addresses, &vlans, now);
        let subnet_vlan_records =
            generate_subnet_vlan_records(&interfaces, &hosts_with_services, now);
        let daemons = generate_daemons(&networks, &hosts, &subnets, now, user_id);
        let api_keys = generate_api_keys(&networks, now);
        let topologies = generate_topologies(&networks, &tags, now);
        let discoveries =
            generate_discoveries(&networks, &subnets, &daemons, &hosts, &credentials, now);
        let shares = generate_shares(&topologies, &networks, user_id, now);
        let user_api_keys = generate_user_api_keys(&networks, organization_id, now);

        let dependencies = generate_dependencies(&networks, &tags, &dep_svc_ids);

        Self {
            tags,
            credentials,
            network_credential_assignments,
            networks,
            subnets,
            vlans,
            subnet_vlan_records,
            hosts_with_services,
            recent_hosts_with_services,
            interfaces,
            neighbor_updates,
            daemons,
            api_keys,
            dependencies,
            topologies,
            discoveries,
            shares,
            user_api_keys,
        }
    }
}

// ============================================================================
// Topologies
// ============================================================================

fn generate_topologies(networks: &[Network], tags: &[Tag], now: DateTime<Utc>) -> Vec<Topology> {
    let critical_tag_id = tags
        .iter()
        .find(|t| t.base.name == "Critical")
        .map(|t| t.id);

    networks
        .iter()
        .map(|network| {
            let mut base = TopologyBase::new(network.id);
            // Add Critical tag to the default ByTag element rule
            if let Some(tag_id) = critical_tag_id {
                let mut request = TopologyRequestOptions::default();
                // Replace the default empty ByTag rule with one that includes Critical
                for rule in &mut request.element_rules {
                    if matches!(rule.rule, ElementRule::ByTag { .. }) {
                        rule.rule = ElementRule::ByTag {
                            tag_ids: vec![tag_id],
                            title: None,
                        };
                    }
                }
                base.options = TopologyOptions {
                    request,
                    ..base.options
                };
            }
            Topology {
                id: Uuid::new_v4(),
                created_at: now,
                updated_at: now,
                base,
            }
        })
        .collect()
}

// ============================================================================
// Tags
// ============================================================================

fn generate_tags(organization_id: Uuid, now: DateTime<Utc>) -> Vec<Tag> {
    // (name, description, color, is_application)
    let tag_definitions: [(&str, &str, Color, bool); 13] = [
        (
            "Production",
            "Systems running in production",
            Color::Red,
            false,
        ),
        (
            "Development",
            "Development and test systems",
            Color::Blue,
            false,
        ),
        (
            "Critical",
            "Business-critical services",
            Color::Orange,
            false,
        ),
        ("Backup Target", "Backup destinations", Color::Green, false),
        (
            "Monitoring",
            "Monitoring infrastructure",
            Color::Purple,
            true,
        ),
        ("Database", "Database servers", Color::Cyan, true),
        ("Web Tier", "Web and application servers", Color::Teal, true),
        ("IoT Device", "Smart devices", Color::Yellow, false),
        (
            "Needs Attention",
            "Requires admin review",
            Color::Rose,
            false,
        ),
        (
            "Managed Client",
            "Client-owned assets",
            Color::Indigo,
            false,
        ),
        (
            "DevOps Pipeline",
            "CI/CD and deployment tools",
            Color::Pink,
            true,
        ),
        ("Storage", "Storage and backup systems", Color::Lime, true),
        ("Messaging", "Message brokers and email", Color::Amber, true),
    ];

    tag_definitions
        .iter()
        .map(|(name, description, color, is_app)| Tag {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            base: TagBase {
                name: name.to_string(),
                description: Some(description.to_string()),
                color: *color,
                organization_id,
                is_application: *is_app,
            },
        })
        .collect()
}

// ============================================================================
// Credentials
// ============================================================================

fn generate_credentials(organization_id: Uuid, now: DateTime<Utc>) -> Vec<Credential> {
    vec![
        Credential {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: CredentialBase {
                organization_id,
                name: "Default SNMPv2c".to_string(),
                credential_type: CredentialType::SnmpV2c {
                    community: SecretValue::Inline {
                        value: SecretString::from("public".to_string()),
                    },
                },
                tags: Vec::new(),
                assigned_network_ids: Vec::new(),
                host_assignments: Vec::new(),
            },
        },
        Credential {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: CredentialBase {
                organization_id,
                name: "Network Devices".to_string(),
                credential_type: CredentialType::SnmpV2c {
                    community: SecretValue::Inline {
                        value: SecretString::from("acme-network".to_string()),
                    },
                },
                tags: Vec::new(),
                assigned_network_ids: Vec::new(),
                host_assignments: Vec::new(),
            },
        },
        Credential {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: CredentialBase {
                organization_id,
                name: "Docker TLS Proxy".to_string(),
                credential_type: CredentialType::DockerProxy {
                    port: 2376,
                    path: None,
                    ssl_cert: None,
                    ssl_key: None,
                    ssl_chain: None,
                },
                tags: Vec::new(),
                assigned_network_ids: Vec::new(),
                host_assignments: Vec::new(),
            },
        },
    ]
}

// ============================================================================
// Network-Credential Assignments
// ============================================================================

fn generate_network_credential_assignments(
    networks: &[Network],
    credentials: &[Credential],
) -> Vec<NetworkCredentialAssignment> {
    let find_network = |name: &str| {
        networks
            .iter()
            .find(|n| n.base.name.contains(name))
            .unwrap()
    };
    let find_cred = |name: &str| {
        credentials
            .iter()
            .find(|c| c.base.name.contains(name))
            .unwrap()
    };

    let default_snmp = find_cred("Default SNMPv2c");
    let network_snmp = find_cred("Network Devices");
    let hq = find_network("Headquarters");
    let dc = find_network("Data Center");

    vec![
        // HQ: both SNMP credentials + Docker proxy
        NetworkCredentialAssignment {
            network_id: hq.id,
            credential_ids: vec![default_snmp.id, network_snmp.id],
        },
        // DC: both SNMP credentials
        NetworkCredentialAssignment {
            network_id: dc.id,
            credential_ids: vec![default_snmp.id, network_snmp.id],
        },
    ]
}

// ============================================================================
// Networks
// ============================================================================

fn generate_networks(
    organization_id: Uuid,
    tags: &[Tag],
    _credentials: &[Credential],
    now: DateTime<Utc>,
) -> Vec<Network> {
    let production_tag = tags
        .iter()
        .find(|t| t.base.name == "Production")
        .map(|t| t.id);

    // Note: credential_ids are hydrated from junction tables, not stored on the network.
    // Network-credential associations would be created via credential_service.set_network_credentials().

    // Stagger timestamps so networks sort in predictable order (Headquarters first)
    vec![
        Network {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: NetworkBase {
                name: "Headquarters".to_string(),
                organization_id,
                tags: production_tag.into_iter().collect(),
                credential_ids: vec![],
                stale_after_hours: Some(48),
            },
            effective_stale_after_hours: 48,
        },
        Network {
            id: Uuid::new_v4(),
            created_at: now + chrono::Duration::seconds(1),
            updated_at: now + chrono::Duration::seconds(1),
            base: NetworkBase {
                name: "Data Center".to_string(),
                organization_id,
                tags: production_tag.into_iter().collect(),
                credential_ids: vec![],
                stale_after_hours: None,
            },
            effective_stale_after_hours: DEFAULT_STALE_AFTER_HOURS,
        },
    ]
}

// ============================================================================
// Subnets
// ============================================================================

fn generate_subnets(
    networks: &[Network],
    tags: &[Tag],
    docker_hq_svc_id: Uuid,
    docker_dc_svc_id: Uuid,
    now: DateTime<Utc>,
) -> Vec<Subnet> {
    let hq = networks
        .iter()
        .find(|n| n.base.name == "Headquarters")
        .unwrap();
    let dc = networks
        .iter()
        .find(|n| n.base.name == "Data Center")
        .unwrap();

    let monitoring_tag = tags
        .iter()
        .find(|t| t.base.name == "Monitoring")
        .map(|t| t.id);

    vec![
        // ===== Headquarters subnets (7) =====
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(10, 0, 1, 0), 24).unwrap()),
                network_id: hq.id,
                name: "HQ Management".to_string(),
                description: Some("Network management and monitoring".to_string()),
                subnet_type: SubnetType::Management,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags: monitoring_tag.into_iter().collect(),
            },
        },
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(10, 0, 10, 0), 24).unwrap()),
                network_id: hq.id,
                name: "HQ Office LAN".to_string(),
                description: Some("Office workstations".to_string()),
                subnet_type: SubnetType::Lan,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags: vec![],
            },
        },
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(10, 0, 20, 0), 24).unwrap()),
                network_id: hq.id,
                name: "HQ Servers".to_string(),
                description: Some("On-premises servers and hypervisors".to_string()),
                subnet_type: SubnetType::Lan,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags: vec![],
            },
        },
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(10, 0, 40, 0), 24).unwrap()),
                network_id: hq.id,
                name: "HQ Storage".to_string(),
                description: Some("Storage area network".to_string()),
                subnet_type: SubnetType::Storage,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags: vec![],
            },
        },
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(10, 0, 30, 0), 24).unwrap()),
                network_id: hq.id,
                name: "HQ IoT".to_string(),
                description: Some("Smart office devices".to_string()),
                subnet_type: SubnetType::IoT,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags: vec![],
            },
        },
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(172, 17, 0, 0), 16).unwrap()),
                network_id: hq.id,
                name: "HQ Docker Bridge".to_string(),
                description: Some("Docker container network".to_string()),
                subnet_type: SubnetType::DockerBridge,
                virtualization_service_id: Some(docker_hq_svc_id),
                source: EntitySource::Manual,
                tags: vec![],
            },
        },
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(10, 0, 100, 0), 24).unwrap()),
                network_id: hq.id,
                name: "HQ Guest WiFi".to_string(),
                description: Some("Guest wireless network".to_string()),
                subnet_type: SubnetType::Guest,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags: vec![],
            },
        },
        // ===== Data Center subnets (6) =====
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(172, 16, 0, 0), 24).unwrap()),
                network_id: dc.id,
                name: "DC Management".to_string(),
                description: Some("Data center management network".to_string()),
                subnet_type: SubnetType::Management,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags: monitoring_tag.into_iter().collect(),
            },
        },
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(172, 16, 10, 0), 24).unwrap()),
                network_id: dc.id,
                name: "DC Compute".to_string(),
                description: Some("Compute and hypervisor hosts".to_string()),
                subnet_type: SubnetType::Lan,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags: vec![],
            },
        },
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(172, 16, 20, 0), 24).unwrap()),
                network_id: dc.id,
                name: "DC Storage".to_string(),
                description: Some("Storage network".to_string()),
                subnet_type: SubnetType::Storage,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags: vec![],
            },
        },
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(172, 16, 30, 0), 24).unwrap()),
                network_id: dc.id,
                name: "DC DMZ".to_string(),
                description: Some("Demilitarized zone for public-facing services".to_string()),
                subnet_type: SubnetType::Dmz,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags: vec![],
            },
        },
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(172, 18, 0, 0), 16).unwrap()),
                network_id: dc.id,
                name: "DC Docker Bridge".to_string(),
                description: Some("Docker container network".to_string()),
                subnet_type: SubnetType::DockerBridge,
                virtualization_service_id: Some(docker_dc_svc_id),
                source: EntitySource::Manual,
                tags: vec![],
            },
        },
        Subnet {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: SubnetBase {
                cidr: IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(10, 8, 0, 0), 24).unwrap()),
                network_id: dc.id,
                name: "DC VPN Tunnel".to_string(),
                description: Some("VPN tunnel to headquarters".to_string()),
                subnet_type: SubnetType::VpnTunnel,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags: vec![],
            },
        },
    ]
}

// ============================================================================
// Hosts and Services
// ============================================================================

/// Helper to create a host with a single interface.
/// Returns (Host,IPAddress) - host has ip_address_ids: vec![] initially,
/// the server will populate it after creating the interface.
#[allow(clippy::too_many_arguments)]
fn create_host(
    name: &str,
    hostname: Option<&str>,
    description: Option<&str>,
    network: &Network,
    subnet: &Subnet,
    ip: Ipv4Addr,
    tags: Vec<Uuid>,
    _snmp_credential_id: Option<Uuid>,
    virtualization: Option<(HostVirtualization, Uuid)>,
    now: DateTime<Utc>,
) -> (Host, IPAddress) {
    let (virtualization_metadata, virtualization_service_id) = match virtualization {
        Some((metadata, service_id)) => (Some(metadata), Some(service_id)),
        None => (None, None),
    };
    let host_id = Uuid::new_v4();
    let ip_address = IPAddress {
        valid_from: now,
        valid_to: None,
        lineage_id: None,
        last_seen_at: now,
        last_discovery_id: None,
        first_discovery_id: None,
        id: Uuid::new_v4(),
        created_at: now,
        updated_at: now,
        base: IPAddressBase {
            network_id: network.id,
            host_id,
            subnet_id: subnet.id,
            ip_address: IpAddr::V4(ip),
            mac_address: None,
            name: Some("eth0".to_string()),
            position: 0,
        },
    };
    let host = Host {
        valid_from: now,
        valid_to: None,
        lineage_id: None,
        last_seen_at: now,
        last_discovery_id: None,
        first_discovery_id: None,
        id: host_id,
        created_at: now,
        updated_at: now,
        base: HostBase {
            name: HostName::Manual(name.to_string()),
            network_id: network.id,
            hostname: hostname.map(String::from),
            hostname_authoritative: true,
            description: description.map(String::from),
            source: EntitySource::Manual,
            virtualization_metadata,
            virtualization_service_id,
            hidden: false,
            tags,
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
        },
    };
    (host, ip_address)
}

/// Wraps a `create_host()` result to add SNMP system information fields.
#[allow(clippy::too_many_arguments)]
fn with_snmp(
    (mut host, ip_address): (Host, IPAddress),
    sys_descr: Option<&str>,
    sys_object_id: Option<&str>,
    sys_location: Option<&str>,
    sys_contact: Option<&str>,
    chassis_id: Option<&str>,
    manufacturer: Option<&str>,
    model: Option<&str>,
    serial_number: Option<&str>,
) -> (Host, IPAddress) {
    host.base.sys_descr = sys_descr.map(String::from);
    host.base.sys_object_id = sys_object_id.map(String::from);
    host.base.sys_location = sys_location.map(String::from);
    host.base.sys_contact = sys_contact.map(String::from);
    host.base.chassis_id = chassis_id.map(String::from);
    // SNMP sysName conventionally mirrors the device hostname.
    host.base.sys_name = Some(host.base.name.to_string());
    host.base.manufacturer = manufacturer.map(str::to_string);
    host.base.model = model.map(str::to_string);
    host.base.serial_number = serial_number.map(str::to_string);
    (host, ip_address)
}

/// Wraps a `create_host()` result to set the MAC address on the IP address.
fn with_mac((host, mut ip_address): (Host, IPAddress), mac: [u8; 6]) -> (Host, IPAddress) {
    ip_address.base.mac_address = Some(MacAddress::new(mac));
    (host, ip_address)
}

/// Helper to create a service for a host.
/// Returns (Service, Option<Port>) - the port must be added to the host's ports list.
fn create_service(
    service_def_id: &str,
    name: &str,
    host: &Host,
    ip_address: &IPAddress,
    port_type: Option<PortType>,
    tags: Vec<Uuid>,
    now: DateTime<Utc>,
) -> Option<(Service, Option<Port>)> {
    let service_definition = ServiceDefinitionRegistry::find_by_id(service_def_id)?;

    let (bindings, port) = if let Some(pt) = port_type {
        let port = Port::new_hostless(pt);
        let binding = Binding::new_port_serviceless(port.id, Some(ip_address.id));
        (vec![binding], Some(port))
    } else {
        let binding = Binding::new_ip_address_serviceless(ip_address.id);
        (vec![binding], None)
    };

    Some((
        Service {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: ServiceBase {
                host_id: host.id,
                network_id: host.base.network_id,
                service_definition,
                name: name.to_string(),
                bindings,
                virtualization_metadata: None,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags,
                position: 0,
            },
        },
        port,
    ))
}

/// Like `create_service` but accepts a pre-generated UUID for the service ID.
/// Used for Proxmox VE and Docker Daemon services that must have known IDs
/// before VM hosts/container services reference them.
#[allow(clippy::too_many_arguments)]
fn create_service_with_id(
    service_id: Uuid,
    service_def_id: &str,
    name: &str,
    host: &Host,
    ip_address: &IPAddress,
    port_type: Option<PortType>,
    tags: Vec<Uuid>,
    now: DateTime<Utc>,
) -> Option<(Service, Option<Port>)> {
    let service_definition = ServiceDefinitionRegistry::find_by_id(service_def_id)?;

    let (bindings, port) = if let Some(pt) = port_type {
        let port = Port::new_hostless(pt);
        let binding = Binding::new_port_serviceless(port.id, Some(ip_address.id));
        (vec![binding], Some(port))
    } else {
        let binding = Binding::new_ip_address_serviceless(ip_address.id);
        (vec![binding], None)
    };

    Some((
        Service {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: service_id,
            created_at: now,
            updated_at: now,
            base: ServiceBase {
                host_id: host.id,
                network_id: host.base.network_id,
                service_definition,
                name: name.to_string(),
                bindings,
                virtualization_metadata: None,
                virtualization_service_id: None,
                source: EntitySource::Manual,
                tags,
                position: 0,
            },
        },
        port,
    ))
}

/// Create a Docker container service with ServiceVirtualization::Docker.
/// Binds service to the given interface (typically docker0).
#[allow(clippy::too_many_arguments)]
fn create_container_service(
    service_def_id: &str,
    name: &str,
    host: &Host,
    ip_address: &IPAddress,
    port_type: Option<PortType>,
    container_name: &str,
    container_id: &str,
    docker_daemon_svc_id: Uuid,
    tags: Vec<Uuid>,
    now: DateTime<Utc>,
) -> Option<(Service, Option<Port>)> {
    let service_definition = ServiceDefinitionRegistry::find_by_id(service_def_id)?;

    let (bindings, port) = if let Some(pt) = port_type {
        let port = Port::new_hostless(pt);
        let binding = Binding::new_port_serviceless(port.id, Some(ip_address.id));
        (vec![binding], Some(port))
    } else {
        let binding = Binding::new_ip_address_serviceless(ip_address.id);
        (vec![binding], None)
    };

    Some((
        Service {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: ServiceBase {
                host_id: host.id,
                network_id: host.base.network_id,
                service_definition,
                name: name.to_string(),
                bindings,
                virtualization_metadata: Some(ServiceVirtualization::Docker(
                    DockerVirtualization {
                        container_name: Some(container_name.to_string()),
                        container_id: Some(container_id.to_string()),
                        compose_project: Some("media-stack".to_string()),
                    },
                )),
                virtualization_service_id: Some(docker_daemon_svc_id),
                source: EntitySource::Manual,
                tags,
                position: 0,
            },
        },
        port,
    ))
}

/// Helper macro to create a host with its services bundled together.
/// Ports are collected separately and bundled with the host.
/// Takes a tuple of (Host,IPAddress) from create_host().
macro_rules! host_with_services {
    ($host_tuple:expr, $now:expr, $( ($svc_def:expr, $svc_name:expr, $port:expr, $tags:expr) ),* $(,)?) => {{
        let (host, ip_address) = $host_tuple;
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        $(
            if let Some((svc, port)) = create_service($svc_def, $svc_name, &host, &ip_addresses[0], $port, $tags, $now) {
                // Collect port separately if present
                if let Some(p) = port {
                    ports.push(p);
                }
                services.push(svc);
            }
        )*
        HostWithServices { host, ip_addresses, ports, services }
    }};
}

/// A small set of "recently discovered" hosts, created AFTER the per-network
/// snapshot in the populate handler so the snapshot captures an earlier state
/// and the live view visibly differs (these hosts/services appear only in
/// live). Kept fully self-contained — no dependencies, neighbor links, or
/// interfaces — so they can be inserted after the main batch without
/// FK-ordering concerns. Uses only service-definition ids already proven in the
/// main demo set.
fn generate_recent_hosts(
    networks: &[Network],
    subnets: &[Subnet],
    now: DateTime<Utc>,
) -> Vec<HostWithServices> {
    let find_network = |name: &str| {
        networks
            .iter()
            .find(|n| n.base.name.contains(name))
            .unwrap()
    };
    let find_subnet = |name: &str| subnets.iter().find(|s| s.base.name.contains(name)).unwrap();

    let hq = find_network("Headquarters");
    let dc = find_network("Data Center");

    vec![
        // HQ: a new employee workstation on the office LAN.
        host_with_services!(
            create_host(
                "hq-ws-jmartin",
                Some("jmartin-pc.acme.local"),
                Some("Workstation — J. Martin (new hire)"),
                hq,
                find_subnet("HQ Office LAN"),
                Ipv4Addr::new(10, 0, 10, 201),
                vec![],
                None,
                None,
                now,
            ),
            now,
            ("Workstation", "Remote Desktop", Some(PortType::Rdp), vec![]),
            ("SSH", "SSH", Some(PortType::Ssh), vec![]),
        ),
        // HQ: a newly stood-up secondary DNS resolver.
        host_with_services!(
            create_host(
                "hq-dns-secondary",
                Some("dns2.acme.local"),
                Some("Secondary DNS resolver (recently added)"),
                hq,
                find_subnet("HQ Servers"),
                Ipv4Addr::new(10, 0, 20, 201),
                vec![],
                None,
                None,
                now,
            ),
            now,
            ("Bind9", "BIND DNS", Some(PortType::DnsUdp), vec![]),
            ("SSH", "SSH", Some(PortType::Ssh), vec![]),
        ),
        // DC: a new VPN gateway.
        host_with_services!(
            create_host(
                "dc-vpn-gw02",
                Some("vpn2.dc.acme.local"),
                Some("VPN gateway (recently added)"),
                dc,
                find_subnet("DC Compute"),
                Ipv4Addr::new(172, 16, 10, 201),
                vec![],
                None,
                None,
                now,
            ),
            now,
            ("OpenVPN", "OpenVPN", Some(PortType::OpenVPN), vec![]),
            ("SSH", "SSH", Some(PortType::Ssh), vec![]),
        ),
        // DC: a new compute node.
        host_with_services!(
            create_host(
                "dc-node07",
                Some("node07.dc.acme.local"),
                Some("Compute node (recently added)"),
                dc,
                find_subnet("DC Compute"),
                Ipv4Addr::new(172, 16, 10, 202),
                vec![],
                None,
                None,
                now,
            ),
            now,
            ("SSH", "SSH", Some(PortType::Ssh), vec![]),
        ),
    ]
}

fn generate_hosts_and_services(
    networks: &[Network],
    subnets: &[Subnet],
    tags: &[Tag],
    credentials: &[Credential],
    dep_svc_ids: &DependencyServiceIds,
    now: DateTime<Utc>,
) -> Vec<HostWithServices> {
    let mut result = Vec::new();

    // Helper to find entities
    let find_network = |name: &str| {
        networks
            .iter()
            .find(|n| n.base.name.contains(name))
            .unwrap()
    };
    let find_subnet = |name: &str| subnets.iter().find(|s| s.base.name.contains(name)).unwrap();
    let find_tag = |name: &str| tags.iter().find(|t| t.base.name == name).map(|t| t.id);

    let network_devices_cred = credentials
        .iter()
        .find(|c| c.base.name == "Network Devices")
        .map(|c| c.id);
    let docker_proxy_cred = credentials
        .iter()
        .find(|c| c.base.name == "Docker TLS Proxy")
        .map(|c| c.id);

    let critical_tag = find_tag("Critical");
    let production_tag = find_tag("Production");
    let database_tag = find_tag("Database");
    let monitoring_tag = find_tag("Monitoring");
    let iot_tag = find_tag("IoT Device");
    let web_tier_tag = find_tag("Web Tier");
    let backup_tag = find_tag("Backup Target");
    let devops_tag = find_tag("DevOps Pipeline");
    let storage_tag = find_tag("Storage");
    let messaging_tag = find_tag("Messaging");

    // Pre-generated service UUIDs for virtualization wiring
    let pve_hq1_svc_id = Uuid::new_v4(); // Proxmox VE on proxmox-hv01
    let pve_hq2_svc_id = Uuid::new_v4(); // Proxmox VE on proxmox-hv02
    let docker_hq_svc_id = dep_svc_ids.docker_hq; // Docker daemon on docker-prod01 (shared with HQ Docker Bridge subnet)
    let pve_dc_svc_id = Uuid::new_v4(); // Proxmox VE on dc-proxmox-hv01
    let docker_dc_svc_id = dep_svc_ids.docker_dc; // Docker daemon on dc-docker01 (shared with DC Docker Bridge subnet)

    // Service UUIDs for HubAndSpoke dependency wiring (pre-generated at top level)
    let prometheus_hq_svc_id = dep_svc_ids.prometheus_hq;
    let grafana_hq_svc_id = dep_svc_ids.grafana_hq;
    let uptime_kuma_svc_id = dep_svc_ids.uptime_kuma;
    // Binding UUIDs for RequestPath dependency wiring (pre-generated at top level)
    let traefik_hq_binding_id = dep_svc_ids.traefik_hq_binding;
    let gitea_hq_binding_id = dep_svc_ids.gitea_hq_binding;
    let haproxy_dc_binding_id = dep_svc_ids.haproxy_dc_binding;
    let app01_dc_binding_id = dep_svc_ids.app01_dc_binding;
    let mariadb_dc_binding_id = dep_svc_ids.mariadb_dc_binding;
    let pve_hq1_binding_id = dep_svc_ids.pve_hq1_binding;
    let truenas_binding_id = dep_svc_ids.truenas_binding;
    // Service UUIDs for DC HubAndSpoke dependency wiring
    let prometheus_dc_svc_id = dep_svc_ids.prometheus_dc;
    let grafana_dc_svc_id = dep_svc_ids.grafana_dc;
    let jaeger_dc_svc_id = dep_svc_ids.jaeger_dc;
    let minio_dc_svc_id = dep_svc_ids.minio_dc;
    let ceph_dc_svc_id = dep_svc_ids.ceph_dc;
    let elasticsearch_dc_svc_id = dep_svc_ids.elasticsearch_dc;

    // ========================================================================
    // HEADQUARTERS NETWORK — 30 hosts
    // ========================================================================
    let hq = find_network("Headquarters");
    let hq_mgmt = find_subnet("HQ Management");
    let hq_servers = find_subnet("HQ Servers");
    let hq_storage = find_subnet("HQ Storage");
    let hq_lan = find_subnet("HQ Office LAN");
    let hq_iot = find_subnet("HQ IoT");
    let hq_docker = find_subnet("HQ Docker Bridge");
    let hq_guest = find_subnet("HQ Guest WiFi");

    // -- Management (10.0.1.x) --

    // 1. pfSense Firewall (Critical) — with host-level SNMP credential override
    let mut pfsense = {
        let (host, ip_address) = with_snmp(
            with_mac(
                create_host(
                    "pfsense-fw01",
                    Some("pfsense-fw01.acme.local"),
                    Some("Primary pfSense firewall"),
                    hq,
                    hq_mgmt,
                    Ipv4Addr::new(10, 0, 1, 1),
                    critical_tag.into_iter().collect(),
                    network_devices_cred,
                    None,
                    now,
                ),
                [0xa4, 0xbe, 0x2b, 0x10, 0x01, 0x01],
            ),
            Some("pfSense 2.7.0-RELEASE (amd64) built on FreeBSD 14.0-CURRENT"),
            Some("1.3.6.1.4.1.12325.1.1"),
            Some("HQ Server Room, Rack A1"),
            Some("netops@acme-corp.com"),
            None,
            Some("Netgate"),
            Some("SG-3100"),
            Some("NG61003370A1F4"),
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((svc, port)) = create_service(
            "pfSense",
            "pfSense",
            &host,
            &ip_addresses[0],
            Some(PortType::Https),
            critical_tag.into_iter().collect(),
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        }
    };
    pfsense.host.base.credential_assignments = network_devices_cred
        .into_iter()
        .map(|id| CredentialAssignment {
            credential_id: id,
            ip_address_ids: None,
        })
        .collect();
    result.push(pfsense);

    // 2. UniFi Controller
    result.push(host_with_services!(
        with_mac(
            create_host(
                "unifi-controller",
                Some("unifi.acme.local"),
                Some("UniFi Network Controller"),
                hq,
                hq_mgmt,
                Ipv4Addr::new(10, 0, 1, 10),
                vec![],
                None,
                None,
                now
            ),
            [0xfc, 0xec, 0xda, 0x10, 0x02, 0x01],
        ),
        now,
        (
            "UniFi Controller",
            "UniFi Controller",
            Some(PortType::Https8443),
            vec![]
        ),
    ));

    // 3. Core switch (48 ports, SNMP/LLDP)
    result.push(host_with_services!(
        with_snmp(
            with_mac(
                create_host(
                    "unifi-usw-48",
                    Some("switch.acme.local"),
                    Some("UniFi Switch 48 PoE"),
                    hq,
                    hq_mgmt,
                    Ipv4Addr::new(10, 0, 1, 3),
                    vec![],
                    network_devices_cred,
                    None,
                    now,
                ),
                [0xfc, 0xec, 0xda, 0x10, 0x03, 0x01],
            ),
            Some("UniFi USW-48-PoE, 6.6.65, Linux 5.4.0"),
            Some("1.3.6.1.4.1.41112.1.6"),
            Some("HQ Server Room, Rack A2"),
            Some("netops@acme-corp.com"),
            Some("78:45:c4:ab:cd:01"),
            Some("Ubiquiti"),
            Some("USW-48-PoE"),
            Some("UI7845C4ABCD01"),
        ),
        now,
        ("SNMP", "SNMP", Some(PortType::Snmp), vec![]),
    ));

    // 4. Pi-hole DNS
    result.push(host_with_services!(
        with_mac(
            create_host(
                "pihole-dns01",
                Some("pihole.acme.local"),
                Some("Pi-hole DNS ad blocker"),
                hq,
                hq_mgmt,
                Ipv4Addr::new(10, 0, 1, 5),
                vec![],
                None,
                None,
                now
            ),
            [0xdc, 0xa6, 0x32, 0x10, 0x04, 0x01],
        ),
        now,
        ("Pi-Hole", "Pi-hole", Some(PortType::Http), vec![]),
    ));

    // 5. Grafana (pre-generated ID for dependency wiring)
    {
        let (host, ip_address) = with_mac(
            create_host(
                "grafana-mon",
                Some("grafana.acme.local"),
                Some("Grafana monitoring dashboard"),
                hq,
                hq_mgmt,
                Ipv4Addr::new(10, 0, 1, 50),
                monitoring_tag.into_iter().collect(),
                None,
                None,
                now,
            ),
            [0xf8, 0xbc, 0x12, 0x10, 0x05, 0x01],
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((svc, port)) = create_service_with_id(
            grafana_hq_svc_id,
            "Grafana",
            "Grafana",
            &host,
            &ip_addresses[0],
            Some(PortType::Http3000),
            monitoring_tag.into_iter().collect(),
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // 6. Prometheus (pre-generated ID for dependency wiring)
    {
        let (host, ip_address) = with_mac(
            create_host(
                "prometheus",
                Some("prometheus.acme.local"),
                Some("Prometheus metrics server"),
                hq,
                hq_mgmt,
                Ipv4Addr::new(10, 0, 1, 51),
                monitoring_tag.into_iter().collect(),
                None,
                None,
                now,
            ),
            [0xf8, 0xbc, 0x12, 0x10, 0x06, 0x01],
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((svc, port)) = create_service_with_id(
            prometheus_hq_svc_id,
            "Prometheus",
            "Prometheus",
            &host,
            &ip_addresses[0],
            Some(PortType::Http9000),
            monitoring_tag.into_iter().collect(),
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // 7. Uptime Kuma (pre-generated ID for dependency wiring)
    {
        let (host, ip_address) = with_mac(
            create_host(
                "uptime-kuma",
                Some("status.acme.local"),
                Some("Uptime Kuma status page"),
                hq,
                hq_mgmt,
                Ipv4Addr::new(10, 0, 1, 52),
                monitoring_tag.into_iter().collect(),
                None,
                None,
                now,
            ),
            [0xf8, 0xbc, 0x12, 0x10, 0x07, 0x01],
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((svc, port)) = create_service_with_id(
            uptime_kuma_svc_id,
            "UptimeKuma",
            "Uptime Kuma",
            &host,
            &ip_addresses[0],
            Some(PortType::Http3000),
            monitoring_tag.into_iter().collect(),
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // -- Servers (10.0.20.x) — hypervisors, VMs, Docker --

    // 8. Proxmox Hypervisor 1 (pre-generated Proxmox VE service ID)
    {
        let (host, ip_address) = with_snmp(
            with_mac(
                create_host(
                    "proxmox-hv01",
                    Some("proxmox-hv01.acme.local"),
                    Some("Proxmox hypervisor node 1"),
                    hq,
                    hq_servers,
                    Ipv4Addr::new(10, 0, 20, 5),
                    production_tag.into_iter().collect(),
                    None,
                    None,
                    now,
                ),
                [0xf8, 0xbc, 0x12, 0x20, 0x08, 0x01],
            ),
            Some("Linux proxmox-hv01 6.8.12-1-pve #1 SMP PVE 6.8.12-1 x86_64"),
            Some("1.3.6.1.4.1.8072.3.2.10"),
            Some("HQ Server Room, Rack B1"),
            Some("sysadmin@acme-corp.com"),
            None,
            Some("Dell Inc."),
            Some("PowerEdge R740"),
            Some("DL7QX2B1PVE1"),
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((mut svc, port)) = create_service_with_id(
            pve_hq1_svc_id,
            "Proxmox VE",
            "Proxmox VE",
            &host,
            &ip_addresses[0],
            Some(PortType::Https8443),
            production_tag.into_iter().collect(),
            now,
        ) {
            svc.base.bindings[0].id = pve_hq1_binding_id;
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        if let Some((svc, port)) = create_service(
            "SSH",
            "SSH",
            &host,
            &ip_addresses[0],
            Some(PortType::Ssh),
            vec![],
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // 9. Proxmox Hypervisor 2 (pre-generated Proxmox VE service ID)
    {
        let (host, ip_address) = with_snmp(
            with_mac(
                create_host(
                    "proxmox-hv02",
                    Some("proxmox-hv02.acme.local"),
                    Some("Proxmox hypervisor node 2"),
                    hq,
                    hq_servers,
                    Ipv4Addr::new(10, 0, 20, 6),
                    production_tag.into_iter().collect(),
                    None,
                    None,
                    now,
                ),
                [0xf8, 0xbc, 0x12, 0x20, 0x09, 0x01],
            ),
            Some("Linux proxmox-hv02 6.8.12-1-pve #1 SMP PVE 6.8.12-1 x86_64"),
            Some("1.3.6.1.4.1.8072.3.2.10"),
            Some("HQ Server Room, Rack B2"),
            Some("sysadmin@acme-corp.com"),
            None,
            Some("Supermicro"),
            Some("AS-2124BT-HNTR"),
            Some("SMC2124B2PVE2"),
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((svc, port)) = create_service_with_id(
            pve_hq2_svc_id,
            "Proxmox VE",
            "Proxmox VE",
            &host,
            &ip_addresses[0],
            Some(PortType::Https8443),
            production_tag.into_iter().collect(),
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        if let Some((svc, port)) = create_service(
            "SSH",
            "SSH",
            &host,
            &ip_addresses[0],
            Some(PortType::Ssh),
            vec![],
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // 10. gitlab-vm — VM on hv01 (vm_id=100)
    result.push(host_with_services!(
        with_mac(
            create_host(
                "gitlab-vm",
                Some("gitlab.acme.local"),
                Some("GitLab instance (VM on proxmox-hv01)"),
                hq,
                hq_servers,
                Ipv4Addr::new(10, 0, 20, 10),
                production_tag.into_iter().collect(),
                None,
                Some((
                    HostVirtualization::Proxmox(ProxmoxVirtualization {
                        vm_name: Some("gitlab-vm".to_string()),
                        vm_id: Some("100".to_string()),
                    }),
                    pve_hq1_svc_id,
                )),
                now
            ),
            [0x52, 0x54, 0x00, 0x20, 0x10, 0x01],
        ),
        now,
        (
            "GitLab",
            "GitLab",
            Some(PortType::Https),
            [production_tag, devops_tag].into_iter().flatten().collect()
        ),
    ));

    // 11. nextcloud-vm — VM on hv01 (vm_id=101)
    result.push(host_with_services!(
        with_mac(
            create_host(
                "nextcloud-vm",
                Some("cloud.acme.local"),
                Some("Nextcloud file sharing (VM on proxmox-hv01)"),
                hq,
                hq_servers,
                Ipv4Addr::new(10, 0, 20, 11),
                production_tag.into_iter().collect(),
                None,
                Some((
                    HostVirtualization::Proxmox(ProxmoxVirtualization {
                        vm_name: Some("nextcloud-vm".to_string()),
                        vm_id: Some("101".to_string()),
                    }),
                    pve_hq1_svc_id,
                )),
                now
            ),
            [0x52, 0x54, 0x00, 0x20, 0x11, 0x01],
        ),
        now,
        (
            "NextCloud",
            "Nextcloud",
            Some(PortType::Https),
            [production_tag, web_tier_tag]
                .into_iter()
                .flatten()
                .collect()
        ),
    ));

    // 12. keycloak-vm — VM on hv02 (vm_id=200)
    result.push(host_with_services!(
        with_mac(
            create_host(
                "keycloak-vm",
                Some("keycloak.acme.local"),
                Some("Keycloak SSO (VM on proxmox-hv02)"),
                hq,
                hq_servers,
                Ipv4Addr::new(10, 0, 20, 12),
                production_tag.into_iter().collect(),
                None,
                Some((
                    HostVirtualization::Proxmox(ProxmoxVirtualization {
                        vm_name: Some("keycloak-vm".to_string()),
                        vm_id: Some("200".to_string()),
                    }),
                    pve_hq2_svc_id,
                )),
                now
            ),
            [0x52, 0x54, 0x00, 0x20, 0x12, 0x01],
        ),
        now,
        (
            "Keycloak",
            "Keycloak",
            Some(PortType::Https8443),
            production_tag.into_iter().collect()
        ),
    ));

    // 13. docker-prod01 — Docker host (2 ip_addresses: eth0 on Servers, docker0 on DockerBridge)
    {
        let host_id = Uuid::new_v4();
        let eth0 = IPAddress {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: IPAddressBase {
                network_id: hq.id,
                host_id,
                subnet_id: hq_servers.id,
                ip_address: IpAddr::V4(Ipv4Addr::new(10, 0, 20, 20)),
                mac_address: Some(MacAddress::new([0xf8, 0xbc, 0x12, 0x20, 0x13, 0x01])),
                name: Some("eth0".to_string()),
                position: 0,
            },
        };
        let docker0 = IPAddress {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: IPAddressBase {
                network_id: hq.id,
                host_id,
                subnet_id: hq_docker.id,
                ip_address: IpAddr::V4(Ipv4Addr::new(172, 17, 0, 1)),
                mac_address: Some(MacAddress::new([0x02, 0x42, 0xac, 0x11, 0x00, 0x01])),
                name: Some("docker0".to_string()),
                position: 1,
            },
        };
        let host = Host {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: host_id,
            created_at: now,
            updated_at: now,
            base: HostBase {
                name: HostName::Manual("docker-prod01".to_string()),
                network_id: hq.id,
                hostname: Some("docker-prod01.acme.local".to_string()),
                hostname_authoritative: true,
                description: Some("Production Docker host".to_string()),
                source: EntitySource::Manual,
                virtualization_metadata: None,
                virtualization_service_id: None,
                hidden: false,
                tags: production_tag.into_iter().collect(),
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
                credential_assignments: docker_proxy_cred
                    .into_iter()
                    .map(|id| CredentialAssignment {
                        credential_id: id,
                        ip_address_ids: None,
                    })
                    .collect(),
            },
        };

        let mut ports = Vec::new();
        let mut services = Vec::new();

        // Docker Daemon service with pre-generated ID on eth0
        if let Some((svc, port)) = create_service_with_id(
            docker_hq_svc_id,
            "Docker",
            "Docker Daemon",
            &host,
            &eth0,
            Some(PortType::Docker),
            vec![],
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        // Portainer on eth0
        if let Some((svc, port)) = create_service(
            "Portainer",
            "Portainer",
            &host,
            &eth0,
            Some(PortType::Http9000),
            [production_tag, devops_tag].into_iter().flatten().collect(),
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }

        // Traefik container (pre-generated binding ID for dependency wiring)
        if let Some((mut svc, port)) = create_container_service(
            "Traefik",
            "Traefik",
            &host,
            &docker0,
            Some(PortType::Https),
            "traefik",
            "a1b2c3d4e5f6",
            docker_hq_svc_id,
            web_tier_tag.into_iter().collect(),
            now,
        ) {
            svc.base.bindings[0].id = traefik_hq_binding_id;
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        // Gitea container (pre-generated binding ID for dependency wiring)
        if let Some((mut svc, port)) = create_container_service(
            "Gitea",
            "Gitea",
            &host,
            &docker0,
            Some(PortType::Http3000),
            "gitea",
            "g7h8i9j0k1l2",
            docker_hq_svc_id,
            devops_tag.into_iter().collect(),
            now,
        ) {
            svc.base.bindings[0].id = gitea_hq_binding_id;
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        // Other container services on docker0
        for (def_id, name, pt, cname, cid, tags) in [
            (
                "Vaultwarden",
                "Vaultwarden",
                Some(PortType::Http8080),
                "vaultwarden",
                "d4e5f6a7b8c9",
                devops_tag.into_iter().collect::<Vec<_>>(),
            ),
            (
                "mailcow",
                "mailcow",
                Some(PortType::Https8443),
                "mailcow",
                "j0k1l2m3n4o5",
                messaging_tag.into_iter().collect::<Vec<_>>(),
            ),
        ] {
            if let Some((svc, port)) = create_container_service(
                def_id,
                name,
                &host,
                &docker0,
                pt,
                cname,
                cid,
                docker_hq_svc_id,
                tags,
                now,
            ) {
                if let Some(p) = port {
                    ports.push(p);
                }
                services.push(svc);
            }
        }

        result.push(HostWithServices {
            host,
            ip_addresses: vec![eth0, docker0],
            ports,
            services,
        });
    }

    // 14. Jenkins CI
    result.push(host_with_services!(
        with_mac(
            create_host(
                "jenkins-ci",
                Some("jenkins.acme.local"),
                Some("Jenkins CI/CD server"),
                hq,
                hq_servers,
                Ipv4Addr::new(10, 0, 20, 30),
                production_tag.into_iter().collect(),
                None,
                None,
                now
            ),
            [0xf8, 0xbc, 0x12, 0x20, 0x14, 0x01],
        ),
        now,
        (
            "Jenkins",
            "Jenkins",
            Some(PortType::Http8080),
            [production_tag, devops_tag].into_iter().flatten().collect()
        ),
    ));

    // 15. WireGuard VPN
    result.push(host_with_services!(
        with_mac(
            create_host(
                "wireguard-vpn",
                Some("vpn.acme.local"),
                Some("WireGuard VPN server"),
                hq,
                hq_servers,
                Ipv4Addr::new(10, 0, 20, 35),
                vec![],
                None,
                None,
                now
            ),
            [0xf8, 0xbc, 0x12, 0x20, 0x15, 0x01],
        ),
        now,
        (
            "WireGuard",
            "WireGuard VPN",
            Some(PortType::Wireguard),
            vec![]
        ),
    ));

    // -- Storage (10.0.40.x) --

    // 16. db-vm — VM on hv02 (vm_id=201)
    result.push(host_with_services!(
        with_mac(
            create_host(
                "db-vm",
                Some("db.acme.local"),
                Some("Database server (VM on proxmox-hv02)"),
                hq,
                hq_storage,
                Ipv4Addr::new(10, 0, 40, 10),
                database_tag.into_iter().chain(critical_tag).collect(),
                None,
                Some((
                    HostVirtualization::Proxmox(ProxmoxVirtualization {
                        vm_name: Some("db-vm".to_string()),
                        vm_id: Some("201".to_string()),
                    }),
                    pve_hq2_svc_id,
                )),
                now
            ),
            [0x52, 0x54, 0x00, 0x40, 0x16, 0x01],
        ),
        now,
        (
            "PostgreSQL",
            "PostgreSQL",
            Some(PortType::PostgreSQL),
            database_tag.into_iter().collect()
        ),
        (
            "Redis",
            "Redis",
            Some(PortType::Redis),
            database_tag.into_iter().collect()
        ),
    ));

    // 17. TrueNAS Primary (pre-generated binding ID for Backup Flow dependency)
    {
        let (host, ip_address) = with_snmp(
            with_mac(
                create_host(
                    "truenas-primary",
                    Some("truenas.acme.local"),
                    Some("Primary NAS storage"),
                    hq,
                    hq_storage,
                    Ipv4Addr::new(10, 0, 40, 20),
                    critical_tag.into_iter().chain(backup_tag).collect(),
                    None,
                    None,
                    now,
                ),
                [0xd0, 0x50, 0x99, 0x40, 0x17, 0x01],
            ),
            Some("TrueNAS SCALE 24.04 (Dragonfish) - Kernel 6.6.44-production+truenas"),
            Some("1.3.6.1.4.1.50536.3"),
            Some("HQ Server Room, Rack C1"),
            Some("sysadmin@acme-corp.com"),
            None,
            Some("iXsystems"),
            Some("TrueNAS Mini X+"),
            Some("IX-TNMXP-2231C0087"),
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((mut svc, port)) = create_service(
            "TrueNAS",
            "TrueNAS",
            &host,
            &ip_addresses[0],
            Some(PortType::Https),
            [backup_tag, storage_tag].into_iter().flatten().collect(),
            now,
        ) {
            svc.base.bindings[0].id = truenas_binding_id;
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        if let Some((svc, port)) = create_service(
            "NFS",
            "NFS",
            &host,
            &ip_addresses[0],
            Some(PortType::Nfs),
            storage_tag.into_iter().collect(),
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // 18. Synology Backup
    result.push(host_with_services!(
        with_snmp(
            with_mac(
                create_host(
                    "synology-backup",
                    Some("synology.acme.local"),
                    Some("Synology backup NAS"),
                    hq,
                    hq_storage,
                    Ipv4Addr::new(10, 0, 40, 21),
                    backup_tag.into_iter().collect(),
                    None,
                    None,
                    now,
                ),
                [0x00, 0x11, 0x32, 0x40, 0x18, 0x01],
            ),
            Some("Synology NAS DS1621+ DSM 7.2.1-69057 Update 5"),
            Some("1.3.6.1.4.1.6574.1"),
            Some("HQ Server Room, Rack C2"),
            Some("sysadmin@acme-corp.com"),
            None,
            Some("Synology"),
            Some("DS1621+"),
            Some("2140PDN6C201"),
        ),
        now,
        (
            "Synology DSM",
            "Synology DSM",
            Some(PortType::Https),
            [backup_tag, storage_tag].into_iter().flatten().collect()
        ),
    ));

    // -- Office LAN (10.0.10.x) --

    // 19-22. Workstations
    for (name, hostname, desc, ip_last, mac_last) in [
        (
            "ws-engineering-01",
            "ws-eng-01.acme.local",
            "Engineering workstation 1",
            101,
            0x19u8,
        ),
        (
            "ws-engineering-02",
            "ws-eng-02.acme.local",
            "Engineering workstation 2",
            102,
            0x20,
        ),
        (
            "ws-accounting-01",
            "ws-acct-01.acme.local",
            "Accounting workstation",
            103,
            0x21,
        ),
        (
            "ws-hr-01",
            "ws-hr-01.acme.local",
            "HR workstation",
            104,
            0x22,
        ),
    ] {
        result.push(host_with_services!(
            with_mac(
                create_host(
                    name,
                    Some(hostname),
                    Some(desc),
                    hq,
                    hq_lan,
                    Ipv4Addr::new(10, 0, 10, ip_last),
                    vec![],
                    None,
                    None,
                    now
                ),
                [0xf8, 0xbc, 0x12, 0x10, mac_last, 0x01],
            ),
            now,
            ("Workstation", "Workstation", Some(PortType::Rdp), vec![]),
        ));
    }

    // -- IoT (10.0.30.x) --

    // 23. UniFi AP Lobby
    result.push(host_with_services!(
        with_snmp(
            with_mac(
                create_host(
                    "unifi-ap-lobby",
                    Some("ap-lobby.acme.local"),
                    Some("UniFi AP - Main Lobby"),
                    hq,
                    hq_iot,
                    Ipv4Addr::new(10, 0, 30, 100),
                    iot_tag.into_iter().collect(),
                    network_devices_cred,
                    None,
                    now,
                ),
                [0xfc, 0xec, 0xda, 0x30, 0x23, 0x01],
            ),
            Some("UniFi U6-Pro, 6.6.65, Linux 5.4.0"),
            Some("1.3.6.1.4.1.41112.1.6"),
            Some("HQ Main Lobby, Ceiling Mount"),
            Some("netops@acme-corp.com"),
            Some("fc:ec:da:aa:bb:01"),
            Some("Ubiquiti"),
            Some("U6-Pro"),
            Some("UIFCECDAAABB01"),
        ),
        now,
        (
            "Unifi Access Point",
            "UniFi AP",
            None,
            iot_tag.into_iter().collect()
        ),
    ));

    // 24. UniFi AP Floor 2
    result.push(host_with_services!(
        with_snmp(
            with_mac(
                create_host(
                    "unifi-ap-floor2",
                    Some("ap-floor2.acme.local"),
                    Some("UniFi AP - Floor 2"),
                    hq,
                    hq_iot,
                    Ipv4Addr::new(10, 0, 30, 101),
                    iot_tag.into_iter().collect(),
                    network_devices_cred,
                    None,
                    now,
                ),
                [0xfc, 0xec, 0xda, 0x30, 0x24, 0x01],
            ),
            Some("UniFi U6-LR, 6.6.65, Linux 5.4.0"),
            Some("1.3.6.1.4.1.41112.1.6"),
            Some("HQ Floor 2, Hallway Ceiling"),
            Some("netops@acme-corp.com"),
            Some("fc:ec:da:aa:bb:02"),
            Some("Ubiquiti"),
            Some("U6-LR"),
            Some("UIFCECDAAABB02"),
        ),
        now,
        (
            "Unifi Access Point",
            "UniFi AP",
            None,
            iot_tag.into_iter().collect()
        ),
    ));

    // 25. Hue Bridge
    result.push(host_with_services!(
        with_mac(
            create_host(
                "hue-bridge",
                None,
                Some("Philips Hue Bridge"),
                hq,
                hq_iot,
                Ipv4Addr::new(10, 0, 30, 10),
                iot_tag.into_iter().collect(),
                None,
                None,
                now
            ),
            [0x00, 0x17, 0x88, 0x30, 0x25, 0x01],
        ),
        now,
        (
            "Philips Hue Bridge",
            "Philips Hue",
            Some(PortType::Https),
            iot_tag.into_iter().collect()
        ),
    ));

    // 26. HP Printer
    result.push(host_with_services!(
        with_snmp(
            with_mac(
                create_host(
                    "printer-hp-main",
                    None,
                    Some("HP LaserJet Pro"),
                    hq,
                    hq_iot,
                    Ipv4Addr::new(10, 0, 30, 50),
                    iot_tag.into_iter().collect(),
                    None,
                    None,
                    now,
                ),
                [0x3c, 0xd9, 0x2b, 0x30, 0x26, 0x01],
            ),
            Some("HP LaserJet Pro MFP M428fdw, Firmware 20230809"),
            Some("1.3.6.1.4.1.11.2.3.9.1"),
            Some("HQ Floor 1, Copy Room"),
            Some("helpdesk@acme-corp.com"),
            None,
            Some("HP"),
            Some("LaserJet Pro MFP M428fdw"),
            Some("CNBRK1F0X8"),
        ),
        now,
        (
            "HP Printer",
            "HP Printer",
            Some(PortType::Ipp),
            iot_tag.into_iter().collect()
        ),
    ));

    // 27. Camera Entrance
    result.push(host_with_services!(
        with_mac(
            create_host(
                "cam-entrance",
                None,
                Some("Entrance security camera"),
                hq,
                hq_iot,
                Ipv4Addr::new(10, 0, 30, 60),
                iot_tag.into_iter().collect(),
                None,
                None,
                now
            ),
            [0xc0, 0x56, 0xe3, 0x30, 0x27, 0x01],
        ),
        now,
        (
            "RTSP Camera",
            "Security Camera",
            Some(PortType::Rtsp),
            iot_tag.into_iter().collect()
        ),
    ));

    // 28. Camera Parking
    result.push(host_with_services!(
        with_mac(
            create_host(
                "cam-parking",
                None,
                Some("Parking lot security camera"),
                hq,
                hq_iot,
                Ipv4Addr::new(10, 0, 30, 61),
                iot_tag.into_iter().collect(),
                None,
                None,
                now
            ),
            [0xc0, 0x56, 0xe3, 0x30, 0x28, 0x01],
        ),
        now,
        (
            "RTSP Camera",
            "Security Camera",
            Some(PortType::Rtsp),
            iot_tag.into_iter().collect()
        ),
    ));

    // -- Guest WiFi (10.0.100.x) --

    // 29. Guest AP
    result.push(host_with_services!(
        with_snmp(
            with_mac(
                create_host(
                    "guest-ap",
                    Some("guest-ap.acme.local"),
                    Some("Guest WiFi access point"),
                    hq,
                    hq_guest,
                    Ipv4Addr::new(10, 0, 100, 1),
                    iot_tag.into_iter().collect(),
                    network_devices_cred,
                    None,
                    now,
                ),
                [0xfc, 0xec, 0xda, 0x00, 0x29, 0x01],
            ),
            Some("UniFi U6-Lite, 6.6.65, Linux 5.4.0"),
            Some("1.3.6.1.4.1.41112.1.6"),
            Some("HQ Guest Lobby, Ceiling Mount"),
            Some("netops@acme-corp.com"),
            Some("fc:ec:da:aa:bb:03"),
            Some("Ubiquiti"),
            Some("U6-Lite"),
            Some("UIFCECDAAABB03"),
        ),
        now,
        (
            "Unifi Access Point",
            "UniFi AP",
            None,
            iot_tag.into_iter().collect()
        ),
    ));

    // 30. Bind9 secondary DNS (Management)
    result.push(host_with_services!(
        with_mac(
            create_host(
                "bind9-dns",
                Some("bind9.acme.local"),
                Some("Bind9 secondary DNS server"),
                hq,
                hq_mgmt,
                Ipv4Addr::new(10, 0, 1, 6),
                vec![],
                None,
                None,
                now
            ),
            [0xf8, 0xbc, 0x12, 0x10, 0x30, 0x01],
        ),
        now,
        ("Bind9", "Bind9", Some(PortType::DnsUdp), vec![]),
    ));

    // ========================================================================
    // DATA CENTER NETWORK — 20 hosts
    // ========================================================================
    let dc = find_network("Data Center");
    let dc_mgmt = find_subnet("DC Management");
    let dc_compute = find_subnet("DC Compute");
    let dc_storage = find_subnet("DC Storage");
    let dc_dmz = find_subnet("DC DMZ");
    let dc_docker = find_subnet("DC Docker Bridge");
    let dc_vpn = find_subnet("DC VPN");

    // -- Management (172.16.0.x) --

    // 1. DC Firewall
    result.push(host_with_services!(
        with_snmp(
            with_mac(
                create_host(
                    "dc-fw01",
                    Some("fw01.dc.acme.io"),
                    Some("Data center firewall"),
                    dc,
                    dc_mgmt,
                    Ipv4Addr::new(172, 16, 0, 1),
                    critical_tag.into_iter().collect(),
                    network_devices_cred,
                    None,
                    now,
                ),
                [0x70, 0x4c, 0xa5, 0xdc, 0x01, 0x01],
            ),
            Some("FortiGate-60F v7.4.3, build 2573, 240514 (GA.F)"),
            Some("1.3.6.1.4.1.12356.101.1"),
            Some("DC-East, Cage 4, Rack 1"),
            Some("netops@acme-corp.com"),
            None,
            Some("Fortinet"),
            Some("FortiGate-60F"),
            Some("FGT60FTK24010123"),
        ),
        now,
        (
            "Fortinet",
            "FortiGate",
            Some(PortType::Https),
            critical_tag.into_iter().collect()
        ),
    ));

    // 2. DC Switch (24 ports, LLDP)
    result.push(host_with_services!(
        with_snmp(
            with_mac(
                create_host(
                    "dc-switch-01",
                    Some("switch-01.dc.acme.io"),
                    Some("Data center managed switch"),
                    dc,
                    dc_mgmt,
                    Ipv4Addr::new(172, 16, 0, 2),
                    vec![],
                    network_devices_cred,
                    None,
                    now,
                ),
                [0x00, 0x1c, 0x73, 0xdc, 0x02, 0x01],
            ),
            Some("Arista DCS-7050SX3-48YC12, EOS-4.32.0F"),
            Some("1.3.6.1.4.1.30065.1.3011.7050.3735.48.3328.12"),
            Some("DC-East, Cage 4, Rack 2"),
            Some("netops@acme-corp.com"),
            Some("78:45:c4:ab:cd:02"),
            Some("Arista Networks"),
            Some("DCS-7050SX3-48YC12"),
            Some("JPE21120CD02"),
        ),
        now,
        ("SNMP", "SNMP", Some(PortType::Snmp), vec![]),
        ("Switch", "Switch", None, vec![]),
    ));

    // 3. Zabbix Monitoring
    result.push(host_with_services!(
        with_mac(
            create_host(
                "zabbix-mon",
                Some("zabbix.dc.acme.io"),
                Some("Zabbix monitoring server"),
                dc,
                dc_mgmt,
                Ipv4Addr::new(172, 16, 0, 10),
                monitoring_tag.into_iter().collect(),
                None,
                None,
                now
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x03, 0x01],
        ),
        now,
        (
            "Zabbix",
            "Zabbix",
            Some(PortType::Http8080),
            monitoring_tag.into_iter().collect()
        ),
    ));

    // -- DMZ (172.16.30.x) --

    // 4. HAProxy Load Balancer (pre-generated ID for dependency wiring)
    {
        let (host, ip_address) = with_mac(
            create_host(
                "haproxy-lb01",
                Some("lb01.dc.acme.io"),
                Some("HAProxy load balancer"),
                dc,
                dc_dmz,
                Ipv4Addr::new(172, 16, 30, 10),
                production_tag
                    .into_iter()
                    .chain(critical_tag)
                    .chain(web_tier_tag)
                    .collect(),
                None,
                None,
                now,
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x04, 0x01],
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((mut svc, port)) = create_service(
            "HAProxy",
            "HAProxy",
            &host,
            &ip_addresses[0],
            Some(PortType::Https),
            web_tier_tag.into_iter().collect(),
            now,
        ) {
            svc.base.bindings[0].id = haproxy_dc_binding_id;
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // 5. App Server 01 (pre-generated Tomcat ID for dependency wiring)
    {
        let (host, ip_address) = with_mac(
            create_host(
                "app-server-01",
                Some("app-01.dc.acme.io"),
                Some("Application server 1"),
                dc,
                dc_dmz,
                Ipv4Addr::new(172, 16, 30, 20),
                production_tag.into_iter().chain(web_tier_tag).collect(),
                None,
                None,
                now,
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x05, 0x01],
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((mut svc, port)) = create_service(
            "Tomcat",
            "Tomcat",
            &host,
            &ip_addresses[0],
            Some(PortType::Http8080),
            web_tier_tag.into_iter().collect(),
            now,
        ) {
            svc.base.bindings[0].id = app01_dc_binding_id;
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        if let Some((svc, port)) = create_service(
            "SSH",
            "SSH",
            &host,
            &ip_addresses[0],
            Some(PortType::Ssh),
            vec![],
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // 6. App Server 02
    result.push(host_with_services!(
        with_mac(
            create_host(
                "app-server-02",
                Some("app-02.dc.acme.io"),
                Some("Application server 2"),
                dc,
                dc_dmz,
                Ipv4Addr::new(172, 16, 30, 21),
                production_tag.into_iter().chain(web_tier_tag).collect(),
                None,
                None,
                now
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x06, 0x01],
        ),
        now,
        (
            "Tomcat",
            "Tomcat",
            Some(PortType::Http8080),
            web_tier_tag.into_iter().collect()
        ),
        ("SSH", "SSH", Some(PortType::Ssh), vec![]),
    ));

    // -- Compute (172.16.10.x) --

    // 7. DC Proxmox Hypervisor (pre-generated Proxmox VE service ID)
    {
        let (host, ip_address) = with_snmp(
            with_mac(
                create_host(
                    "dc-proxmox-hv01",
                    Some("proxmox-hv01.dc.acme.io"),
                    Some("Data center Proxmox hypervisor"),
                    dc,
                    dc_compute,
                    Ipv4Addr::new(172, 16, 10, 5),
                    production_tag.into_iter().collect(),
                    None,
                    None,
                    now,
                ),
                [0xf8, 0xbc, 0x12, 0xdc, 0x07, 0x01],
            ),
            Some("Linux dc-proxmox-hv01 6.8.12-1-pve #1 SMP PVE 6.8.12-1 x86_64"),
            Some("1.3.6.1.4.1.8072.3.2.10"),
            Some("DC-East, Cage 4, Rack 3"),
            Some("sysadmin@acme-corp.com"),
            None,
            Some("Dell Inc."),
            Some("PowerEdge R640"),
            Some("DL9RT4DC07PVE"),
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((svc, port)) = create_service_with_id(
            pve_dc_svc_id,
            "Proxmox VE",
            "Proxmox VE",
            &host,
            &ip_addresses[0],
            Some(PortType::Https8443),
            production_tag.into_iter().collect(),
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        if let Some((svc, port)) = create_service(
            "SSH",
            "SSH",
            &host,
            &ip_addresses[0],
            Some(PortType::Ssh),
            vec![],
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // 8. argocd-vm — VM on dc-proxmox-hv01 (vm_id=300)
    result.push(host_with_services!(
        with_mac(
            create_host(
                "argocd-vm",
                Some("argocd.dc.acme.io"),
                Some("ArgoCD (VM on dc-proxmox-hv01)"),
                dc,
                dc_compute,
                Ipv4Addr::new(172, 16, 10, 10),
                production_tag.into_iter().collect(),
                None,
                Some((
                    HostVirtualization::Proxmox(ProxmoxVirtualization {
                        vm_name: Some("argocd-vm".to_string()),
                        vm_id: Some("300".to_string()),
                    }),
                    pve_dc_svc_id,
                )),
                now
            ),
            [0x52, 0x54, 0x00, 0xdc, 0x08, 0x01],
        ),
        now,
        (
            "ArgoCD",
            "ArgoCD",
            Some(PortType::Https8443),
            [production_tag, devops_tag].into_iter().flatten().collect()
        ),
    ));

    // 9. graylog-vm — VM on dc-proxmox-hv01 (vm_id=301)
    result.push(host_with_services!(
        with_mac(
            create_host(
                "graylog-vm",
                Some("graylog.dc.acme.io"),
                Some("Graylog log management (VM on dc-proxmox-hv01)"),
                dc,
                dc_compute,
                Ipv4Addr::new(172, 16, 10, 11),
                monitoring_tag.into_iter().collect(),
                None,
                Some((
                    HostVirtualization::Proxmox(ProxmoxVirtualization {
                        vm_name: Some("graylog-vm".to_string()),
                        vm_id: Some("301".to_string()),
                    }),
                    pve_dc_svc_id,
                )),
                now
            ),
            [0x52, 0x54, 0x00, 0xdc, 0x09, 0x01],
        ),
        now,
        (
            "Graylog",
            "Graylog",
            Some(PortType::Http9000),
            monitoring_tag.into_iter().collect()
        ),
    ));

    // 10. mariadb-vm — VM on dc-proxmox-hv01 (vm_id=302, on Storage subnet)
    // Pre-generated MariaDB service ID for dependency wiring
    {
        let (host, ip_address) = with_mac(
            create_host(
                "mariadb-vm",
                Some("mariadb.dc.acme.io"),
                Some("MariaDB database (VM on dc-proxmox-hv01)"),
                dc,
                dc_storage,
                Ipv4Addr::new(172, 16, 20, 10),
                database_tag.into_iter().collect(),
                None,
                Some((
                    HostVirtualization::Proxmox(ProxmoxVirtualization {
                        vm_name: Some("mariadb-vm".to_string()),
                        vm_id: Some("302".to_string()),
                    }),
                    pve_dc_svc_id,
                )),
                now,
            ),
            [0x52, 0x54, 0x00, 0xdc, 0x10, 0x01],
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((mut svc, port)) = create_service(
            "MariaDB",
            "MariaDB",
            &host,
            &ip_addresses[0],
            Some(PortType::MySql),
            database_tag.into_iter().collect(),
            now,
        ) {
            svc.base.bindings[0].id = mariadb_dc_binding_id;
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // 11. dc-docker01 — Docker host (2 ip_addresses: eth0 on Compute, docker0 on DC Docker Bridge)
    {
        let host_id = Uuid::new_v4();
        let eth0 = IPAddress {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: IPAddressBase {
                network_id: dc.id,
                host_id,
                subnet_id: dc_compute.id,
                ip_address: IpAddr::V4(Ipv4Addr::new(172, 16, 10, 20)),
                mac_address: Some(MacAddress::new([0xf8, 0xbc, 0x12, 0xdc, 0x11, 0x01])),
                name: Some("eth0".to_string()),
                position: 0,
            },
        };
        let docker0 = IPAddress {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: IPAddressBase {
                network_id: dc.id,
                host_id,
                subnet_id: dc_docker.id,
                ip_address: IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
                mac_address: Some(MacAddress::new([0x02, 0x42, 0xac, 0x12, 0x00, 0x01])),
                name: Some("docker0".to_string()),
                position: 1,
            },
        };
        let host = Host {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: host_id,
            created_at: now,
            updated_at: now,
            base: HostBase {
                name: HostName::Manual("dc-docker01".to_string()),
                network_id: dc.id,
                hostname: Some("docker01.dc.acme.io".to_string()),
                hostname_authoritative: true,
                description: Some("Data center Docker host".to_string()),
                source: EntitySource::Manual,
                virtualization_metadata: None,
                virtualization_service_id: None,
                hidden: false,
                tags: production_tag.into_iter().collect(),
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
                credential_assignments: docker_proxy_cred
                    .into_iter()
                    .map(|id| CredentialAssignment {
                        credential_id: id,
                        ip_address_ids: None,
                    })
                    .collect(),
            },
        };

        let mut ports = Vec::new();
        let mut services = Vec::new();

        // Docker Daemon service with pre-generated ID on eth0
        if let Some((svc, port)) = create_service_with_id(
            docker_dc_svc_id,
            "Docker",
            "Docker Daemon",
            &host,
            &eth0,
            Some(PortType::Docker),
            vec![],
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        // Portainer on eth0
        if let Some((svc, port)) = create_service(
            "Portainer",
            "Portainer",
            &host,
            &eth0,
            Some(PortType::Http9000),
            production_tag.into_iter().collect(),
            now,
        ) {
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }

        // Container services on docker0 (pre-generated IDs for Observability Stack)
        for (def_id, name, pt, cname, cid, override_svc_id) in [
            (
                "Prometheus",
                "Prometheus",
                Some(PortType::new_tcp(9090)),
                "prometheus",
                "p1r2o3m4e5t6",
                Some(prometheus_dc_svc_id),
            ),
            (
                "Grafana",
                "Grafana",
                Some(PortType::Http3000),
                "grafana",
                "g1r2a3f4a5n6",
                Some(grafana_dc_svc_id),
            ),
            (
                "Jaeger",
                "Jaeger",
                Some(PortType::Https),
                "jaeger",
                "j1a2e3g4e5r6",
                Some(jaeger_dc_svc_id),
            ),
            (
                "Loki",
                "Loki",
                Some(PortType::new_tcp(3100)),
                "loki",
                "l1o2k3i4d5c6",
                None,
            ),
        ] {
            if let Some((mut svc, port)) = create_container_service(
                def_id,
                name,
                &host,
                &docker0,
                pt,
                cname,
                cid,
                docker_dc_svc_id,
                monitoring_tag.into_iter().collect(),
                now,
            ) {
                if let Some(id) = override_svc_id {
                    svc.id = id;
                }
                if let Some(p) = port {
                    ports.push(p);
                }
                services.push(svc);
            }
        }

        result.push(HostWithServices {
            host,
            ip_addresses: vec![eth0, docker0],
            ports,
            services,
        });
    }

    // 12. RabbitMQ
    result.push(host_with_services!(
        with_mac(
            create_host(
                "rabbitmq-node01",
                Some("mq.dc.acme.io"),
                Some("RabbitMQ message broker"),
                dc,
                dc_compute,
                Ipv4Addr::new(172, 16, 10, 30),
                production_tag.into_iter().collect(),
                None,
                None,
                now
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x12, 0x01],
        ),
        now,
        (
            "RabbitMQ",
            "RabbitMQ",
            Some(PortType::AMQP),
            [production_tag, messaging_tag]
                .into_iter()
                .flatten()
                .collect()
        ),
    ));

    // 13. Redis Cluster
    result.push(host_with_services!(
        with_mac(
            create_host(
                "redis-cluster01",
                Some("redis.dc.acme.io"),
                Some("Redis cluster node"),
                dc,
                dc_compute,
                Ipv4Addr::new(172, 16, 10, 31),
                database_tag.into_iter().collect(),
                None,
                None,
                now
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x13, 0x01],
        ),
        now,
        (
            "Redis",
            "Redis",
            Some(PortType::Redis),
            database_tag.into_iter().collect()
        ),
    ));

    // -- Storage (172.16.20.x) --

    // 14. MinIO (pre-generated service ID for Storage Tier dependency)
    {
        let (host, ip_address) = with_mac(
            create_host(
                "minio-storage",
                Some("minio.dc.acme.io"),
                Some("MinIO object storage"),
                dc,
                dc_storage,
                Ipv4Addr::new(172, 16, 20, 20),
                backup_tag.into_iter().collect(),
                None,
                None,
                now,
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x14, 0x01],
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((mut svc, port)) = create_service(
            "MinIO",
            "MinIO",
            &host,
            &ip_addresses[0],
            Some(PortType::Https),
            [backup_tag, storage_tag].into_iter().flatten().collect(),
            now,
        ) {
            svc.id = minio_dc_svc_id;
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // 15. Ceph (pre-generated service ID for Storage Tier dependency)
    {
        let (host, ip_address) = with_mac(
            create_host(
                "ceph-node01",
                Some("ceph.dc.acme.io"),
                Some("Ceph storage node"),
                dc,
                dc_storage,
                Ipv4Addr::new(172, 16, 20, 21),
                backup_tag.into_iter().collect(),
                None,
                None,
                now,
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x15, 0x01],
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((mut svc, port)) = create_service(
            "Ceph",
            "Ceph",
            &host,
            &ip_addresses[0],
            None,
            [backup_tag, storage_tag].into_iter().flatten().collect(),
            now,
        ) {
            svc.id = ceph_dc_svc_id;
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // 16. Elasticsearch (pre-generated service ID for Storage Tier dependency)
    {
        let (host, ip_address) = with_mac(
            create_host(
                "elasticsearch-dc",
                Some("es.dc.acme.io"),
                Some("Elasticsearch cluster"),
                dc,
                dc_storage,
                Ipv4Addr::new(172, 16, 20, 30),
                database_tag.into_iter().collect(),
                None,
                None,
                now,
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x16, 0x01],
        );
        let ip_addresses = vec![ip_address];
        let mut ports = Vec::new();
        let mut services = Vec::new();
        if let Some((mut svc, port)) = create_service(
            "Elasticsearch",
            "Elasticsearch",
            &host,
            &ip_addresses[0],
            Some(PortType::Elasticsearch),
            database_tag.into_iter().collect(),
            now,
        ) {
            svc.id = elasticsearch_dc_svc_id;
            if let Some(p) = port {
                ports.push(p);
            }
            services.push(svc);
        }
        result.push(HostWithServices {
            host,
            ip_addresses,
            ports,
            services,
        });
    }

    // 17. InfluxDB
    result.push(host_with_services!(
        with_mac(
            create_host(
                "influxdb-metrics",
                Some("influxdb.dc.acme.io"),
                Some("InfluxDB metrics store"),
                dc,
                dc_storage,
                Ipv4Addr::new(172, 16, 20, 31),
                database_tag.into_iter().chain(monitoring_tag).collect(),
                None,
                None,
                now
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x17, 0x01],
        ),
        now,
        (
            "InfluxDB",
            "InfluxDB",
            Some(PortType::InfluxDb),
            database_tag.into_iter().collect()
        ),
    ));

    // -- VPN Tunnel (10.8.0.x) --

    // 18. DC VPN
    result.push(host_with_services!(
        with_mac(
            create_host(
                "dc-vpn",
                Some("vpn.dc.acme.io"),
                Some("Data center VPN endpoint"),
                dc,
                dc_vpn,
                Ipv4Addr::new(10, 8, 0, 1),
                vec![],
                None,
                None,
                now
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x18, 0x01],
        ),
        now,
        ("OpenVPN", "OpenVPN", Some(PortType::OpenVPN), vec![]),
    ));

    // -- Additional --

    // 19. Cloudflared Tunnel (DMZ)
    result.push(host_with_services!(
        with_mac(
            create_host(
                "cloudflared-tunnel",
                Some("cloudflared.dc.acme.io"),
                Some("Cloudflare tunnel endpoint"),
                dc,
                dc_dmz,
                Ipv4Addr::new(172, 16, 30, 5),
                production_tag.into_iter().collect(),
                None,
                None,
                now
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x19, 0x01],
        ),
        now,
        (
            "Cloudflared",
            "Cloudflared",
            Some(PortType::Https),
            production_tag.into_iter().collect()
        ),
    ));

    // 20. DC Admin Workstation (Compute)
    result.push(host_with_services!(
        with_mac(
            create_host(
                "dc-ws-admin",
                Some("ws-admin.dc.acme.io"),
                Some("DC admin workstation"),
                dc,
                dc_compute,
                Ipv4Addr::new(172, 16, 10, 100),
                vec![],
                None,
                None,
                now
            ),
            [0xf8, 0xbc, 0x12, 0xdc, 0x20, 0x01],
        ),
        now,
        ("Workstation", "Workstation", Some(PortType::Rdp), vec![]),
        ("SSH", "SSH", Some(PortType::Ssh), vec![]),
    ));

    result
}

// ============================================================================
// IfEntries (SNMP Interface Data)
// ============================================================================

// ============================================================================
// VLANs
// ============================================================================

fn generate_vlans(networks: &[Network], organization_id: Uuid, now: DateTime<Utc>) -> Vec<Vlan> {
    let mut vlans = Vec::new();

    let vlan_defs: Vec<(u16, &str)> = vec![
        (1, "Default"),
        (10, "Management"),
        (20, "Servers"),
        (30, "Users"),
        (100, "Guest"),
    ];

    for network in networks {
        for &(vlan_number, name) in &vlan_defs {
            vlans.push(Vlan {
                id: Uuid::new_v4(),
                created_at: now,
                updated_at: now,
                valid_from: now,
                valid_to: None,
                lineage_id: None,
                last_seen_at: now,
                last_discovery_id: None,
                first_discovery_id: None,
                base: VlanBase {
                    vlan_number,
                    name: name.to_string(),
                    description: None,
                    network_id: network.id,
                    organization_id,
                    source: EntitySource::Discovery,
                    subnet_ids: Vec::new(),
                },
            });
        }
    }

    vlans
}

/// Derive subnet↔VLAN junction rows the same way the server's
/// `reconcile_subnet_vlans_for_host` does at discovery time: a VLAN links to a
/// subnet when an interface whose `native_vlan_id` is that VLAN is attached
/// (via `ip_address_id`) to an IP address on that subnet. Only `native_vlan_id`
/// counts — tagged/trunk `vlan_ids` do not create subnet links. Deduped on
/// `(subnet_id, vlan_id)`.
fn generate_subnet_vlan_records(
    interfaces: &[Interface],
    hosts_with_services: &[HostWithServices],
    now: DateTime<Utc>,
) -> Vec<SubnetVlanRecord> {
    use std::collections::{HashMap, HashSet};

    // ip_address_id → subnet_id, from every host's IP addresses.
    let ip_to_subnet: HashMap<Uuid, Uuid> = hosts_with_services
        .iter()
        .flat_map(|h| h.ip_addresses.iter())
        .map(|ip| (ip.id, ip.base.subnet_id))
        .collect();

    let mut seen: HashSet<(Uuid, Uuid)> = HashSet::new();
    let mut records = Vec::new();
    for iface in interfaces {
        if let (Some(vlan_id), Some(ip_id)) = (iface.base.native_vlan_id, iface.base.ip_address_id)
            && let Some(&subnet_id) = ip_to_subnet.get(&ip_id)
            && seen.insert((subnet_id, vlan_id))
        {
            records.push(SubnetVlanRecord {
                id: Uuid::new_v4(),
                created_at: now,
                valid_from: now,
                valid_to: None,
                lineage_id: None,
                base: SubnetVlanRecordBase::new(subnet_id, vlan_id),
            });
        }
    }
    records
}

/// Build the SNMP interface rows for the demo hosts, plus the neighbor links
/// that `run_populate_demo` resolves to IDs once the hosts exist.
///
/// `neighbor_interface_id` is a self-FK to `interfaces(id)`, and the whole set is
/// inserted by one non-transactional `create_many`. That resolves today only
/// because all ~85 rows fit in a single chunk (36 bound columns per row, so
/// 65535 / 36 = 1820 rows per chunk), leaving a row free to reference a later row
/// in the same statement. Adding switches past that boundary would make a chunk-1
/// row pointing at a chunk-2 row fail deterministically — at which point the
/// insert needs one shared transaction with the FK deferred, not smaller chunks.
fn generate_interfaces(
    networks: &[Network],
    hosts: &[&Host],
    ip_addresses: &[&IPAddress],
    vlans: &[Vlan],
    now: DateTime<Utc>,
) -> (Vec<Interface>, Vec<NeighborUpdate>) {
    let mut interfaces = Vec::new();
    let mut neighbor_updates = Vec::new();

    let find_host = |name: &str| hosts.iter().find(|h| h.base.name == name).copied();
    let find_ip_address = |host_id: Uuid| {
        ip_addresses
            .iter()
            .find(|i| i.base.host_id == host_id)
            .copied()
    };

    // VLAN lookup: (network_id, vlan_number) → VLAN entity UUID
    let find_vlan = |network_id: Uuid, vlan_number: u16| -> Option<Uuid> {
        vlans
            .iter()
            .find(|v| v.base.network_id == network_id && v.base.vlan_number == vlan_number)
            .map(|v| v.id)
    };
    let find_vlans = |network_id: Uuid, vlan_numbers: &[u16]| -> Option<Vec<Uuid>> {
        let ids: Vec<Uuid> = vlan_numbers
            .iter()
            .filter_map(|&n| find_vlan(network_id, n))
            .collect();
        if ids.is_empty() { None } else { Some(ids) }
    };

    // HQ switch MAC (used as chassis ID)
    let hq_switch_mac = "78:45:c4:ab:cd:01";
    // DC switch MAC
    let dc_switch_mac = "78:45:c4:ab:cd:02";

    // ========================================================================
    // HQ: pfSense firewall — multiple ip_addresses
    // ========================================================================
    if let Some(host) = find_host("pfsense-fw01") {
        let network = networks
            .iter()
            .find(|n| n.id == host.base.network_id)
            .unwrap();
        let ip_address = find_ip_address(host.id);

        // WAN interface
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 1,
                if_descr: "igb0".to_string(),
                if_name: None,
                if_alias: Some("WAN".to_string()),
                if_type: 6,
                speed_bps: Some(1_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xa4, 0xbe, 0x2b, 0x10, 0x01, 0x10])),
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
            },
        });

        // LAN interface — connected to HQ switch port 1
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 2,
                if_descr: "igb1".to_string(),
                if_name: None,
                if_alias: Some("LAN".to_string()),
                if_type: 6,
                speed_bps: Some(1_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xa4, 0xbe, 0x2b, 0x10, 0x01, 0x11])),
                ip_address_id: ip_address.map(|i| i.id),
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress(hq_switch_mac.to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("Port 1/0/1".to_string())),
                lldp_sys_name: Some("unifi-usw-48".to_string()),
                lldp_port_desc: Some("Port 1 - pfSense uplink".to_string()),
                lldp_mgmt_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 3))),
                lldp_sys_desc: Some("UniFi USW-48-PoE".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 1),
                vlan_ids: find_vlans(network.id, &[10, 20, 30, 100]),
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "pfsense-fw01".to_string(),
            source_if_index: 2,
            target_host_name: "unifi-usw-48".to_string(),
            target_if_index: 1,
        });

        // OPT1 interface (disabled)
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 3,
                if_descr: "igb2".to_string(),
                if_name: None,
                if_alias: Some("OPT1".to_string()),
                if_type: 6,
                speed_bps: Some(1_000_000_000),
                admin_status: IfAdminStatus::Down,
                oper_status: IfOperStatus::Down,
                mac_address: Some(MacAddress::new([0xa4, 0xbe, 0x2b, 0x10, 0x01, 0x12])),
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
            },
        });
    }

    // ========================================================================
    // HQ: TrueNAS — bonded ip_addresses, connected to switch port 2
    // ========================================================================
    if let Some(host) = find_host("truenas-primary") {
        let network = networks
            .iter()
            .find(|n| n.id == host.base.network_id)
            .unwrap();
        let ip_address = find_ip_address(host.id);

        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 1,
                if_descr: "lagg0".to_string(),
                if_name: None,
                if_alias: Some("LACP Bond".to_string()),
                if_type: 161,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xd0, 0x50, 0x99, 0x40, 0x17, 0x10])),
                ip_address_id: ip_address.map(|i| i.id),
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress(hq_switch_mac.to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("Port 1/0/2".to_string())),
                lldp_sys_name: Some("unifi-usw-48".to_string()),
                lldp_port_desc: Some("Port 2 - TrueNAS uplink".to_string()),
                lldp_mgmt_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 3))),
                lldp_sys_desc: Some("UniFi USW-48-PoE".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "truenas-primary".to_string(),
            source_if_index: 1,
            target_host_name: "unifi-usw-48".to_string(),
            target_if_index: 2,
        });
    }

    // ========================================================================
    // HQ: Proxmox HV01 — with loopback, connected to switch port 3
    // ========================================================================
    if let Some(host) = find_host("proxmox-hv01") {
        let network = networks
            .iter()
            .find(|n| n.id == host.base.network_id)
            .unwrap();
        let ip_address = find_ip_address(host.id);

        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 1,
                if_descr: "eno1".to_string(),
                if_name: None,
                if_alias: Some("Primary NIC".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xf8, 0xbc, 0x12, 0x20, 0x08, 0x10])),
                ip_address_id: ip_address.map(|i| i.id),
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress(hq_switch_mac.to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("Port 1/0/3".to_string())),
                lldp_sys_name: Some("unifi-usw-48".to_string()),
                lldp_port_desc: Some("Port 3 - Proxmox HV01 uplink".to_string()),
                lldp_mgmt_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 3))),
                lldp_sys_desc: Some("UniFi USW-48-PoE".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "proxmox-hv01".to_string(),
            source_if_index: 1,
            target_host_name: "unifi-usw-48".to_string(),
            target_if_index: 3,
        });

        // Loopback
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 2,
                if_descr: "lo".to_string(),
                if_name: None,
                if_alias: None,
                if_type: 24,
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
            },
        });
    }

    // ========================================================================
    // HQ: Proxmox HV02 — connected to switch port 4
    // ========================================================================
    if let Some(host) = find_host("proxmox-hv02") {
        let network = networks
            .iter()
            .find(|n| n.id == host.base.network_id)
            .unwrap();
        let ip_address = find_ip_address(host.id);

        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 1,
                if_descr: "eno1".to_string(),
                if_name: None,
                if_alias: Some("Primary NIC".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xf8, 0xbc, 0x12, 0x20, 0x09, 0x10])),
                ip_address_id: ip_address.map(|i| i.id),
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress(hq_switch_mac.to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("Port 1/0/4".to_string())),
                lldp_sys_name: Some("unifi-usw-48".to_string()),
                lldp_port_desc: Some("Port 4 - Proxmox HV02 uplink".to_string()),
                lldp_mgmt_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 3))),
                lldp_sys_desc: Some("UniFi USW-48-PoE".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "proxmox-hv02".to_string(),
            source_if_index: 1,
            target_host_name: "unifi-usw-48".to_string(),
            target_if_index: 4,
        });
    }

    // ========================================================================
    // HQ: docker-prod01 — connected to switch port 5
    // ========================================================================
    if let Some(host) = find_host("docker-prod01") {
        let network = networks
            .iter()
            .find(|n| n.id == host.base.network_id)
            .unwrap();
        let ip_address = find_ip_address(host.id);

        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 1,
                if_descr: "eth0".to_string(),
                if_name: None,
                if_alias: Some("Primary NIC".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xf8, 0xbc, 0x12, 0x20, 0x13, 0x10])),
                ip_address_id: ip_address.map(|i| i.id),
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress(hq_switch_mac.to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("Port 1/0/5".to_string())),
                lldp_sys_name: Some("unifi-usw-48".to_string()),
                lldp_port_desc: Some("Port 5 - Docker host uplink".to_string()),
                lldp_mgmt_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 3))),
                lldp_sys_desc: Some("UniFi USW-48-PoE".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "docker-prod01".to_string(),
            source_if_index: 1,
            target_host_name: "unifi-usw-48".to_string(),
            target_if_index: 5,
        });
    }

    // ========================================================================
    // HQ Switch — unifi-usw-48 (48 ports)
    // ========================================================================
    if let Some(host) = find_host("unifi-usw-48") {
        let network = networks
            .iter()
            .find(|n| n.id == host.base.network_id)
            .unwrap();
        let ip_address = find_ip_address(host.id);

        let pfsense_host = find_host("pfsense-fw01");
        let truenas_host = find_host("truenas-primary");
        let proxmox_hv01 = find_host("proxmox-hv01");
        let proxmox_hv02 = find_host("proxmox-hv02");
        let docker_host = find_host("docker-prod01");
        let ap_host = find_host("unifi-ap-lobby");

        // Port 1 ↔ pfsense-fw01
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 1,
                if_descr: "Port 1/0/1".to_string(),
                if_name: None,
                if_alias: Some("pfSense uplink".to_string()),
                if_type: 6,
                speed_bps: Some(1_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xfc, 0xec, 0xda, 0x10, 0x03, 0x01])),
                ip_address_id: ip_address.map(|i| i.id),
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress("00:0d:b9:4a:f2:01".to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("igb1".to_string())),
                lldp_sys_name: Some("pfsense-fw01".to_string()),
                lldp_port_desc: Some("LAN".to_string()),
                lldp_mgmt_addr: pfsense_host
                    .map(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 1))),
                lldp_sys_desc: Some("pfSense 2.7.0-RELEASE".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 1),
                vlan_ids: find_vlans(network.id, &[10, 20, 30, 100]),
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "unifi-usw-48".to_string(),
            source_if_index: 1,
            target_host_name: "pfsense-fw01".to_string(),
            target_if_index: 2,
        });

        // Port 2 ↔ truenas-primary
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 2,
                if_descr: "Port 1/0/2".to_string(),
                if_name: None,
                if_alias: Some("TrueNAS uplink".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xfc, 0xec, 0xda, 0x10, 0x03, 0x02])),
                ip_address_id: None,
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress("3c:ec:ef:12:34:01".to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("lagg0".to_string())),
                lldp_sys_name: Some("truenas-primary".to_string()),
                lldp_port_desc: Some("LACP Bond".to_string()),
                lldp_mgmt_addr: truenas_host
                    .map(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 40, 20))),
                lldp_sys_desc: Some("TrueNAS SCALE".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "unifi-usw-48".to_string(),
            source_if_index: 2,
            target_host_name: "truenas-primary".to_string(),
            target_if_index: 1,
        });

        // Port 3 ↔ proxmox-hv01
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 3,
                if_descr: "Port 1/0/3".to_string(),
                if_name: None,
                if_alias: Some("Proxmox HV01 uplink".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xfc, 0xec, 0xda, 0x10, 0x03, 0x03])),
                ip_address_id: None,
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress("d4:be:d9:56:78:01".to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("eno1".to_string())),
                lldp_sys_name: Some("proxmox-hv01".to_string()),
                lldp_port_desc: Some("Primary NIC".to_string()),
                lldp_mgmt_addr: proxmox_hv01
                    .map(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 20, 5))),
                lldp_sys_desc: Some("Proxmox VE 8.1".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "unifi-usw-48".to_string(),
            source_if_index: 3,
            target_host_name: "proxmox-hv01".to_string(),
            target_if_index: 1,
        });

        // Port 4 ↔ proxmox-hv02
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 4,
                if_descr: "Port 1/0/4".to_string(),
                if_name: None,
                if_alias: Some("Proxmox HV02 uplink".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xfc, 0xec, 0xda, 0x10, 0x03, 0x04])),
                ip_address_id: None,
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress("d4:be:d9:56:78:02".to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("eno1".to_string())),
                lldp_sys_name: Some("proxmox-hv02".to_string()),
                lldp_port_desc: Some("Primary NIC".to_string()),
                lldp_mgmt_addr: proxmox_hv02
                    .map(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 20, 6))),
                lldp_sys_desc: Some("Proxmox VE 8.1".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "unifi-usw-48".to_string(),
            source_if_index: 4,
            target_host_name: "proxmox-hv02".to_string(),
            target_if_index: 1,
        });

        // Port 5 ↔ docker-prod01
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 5,
                if_descr: "Port 1/0/5".to_string(),
                if_name: None,
                if_alias: Some("Docker host uplink".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xfc, 0xec, 0xda, 0x10, 0x03, 0x05])),
                ip_address_id: None,
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress("aa:bb:cc:dd:ee:01".to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("eth0".to_string())),
                lldp_sys_name: Some("docker-prod01".to_string()),
                lldp_port_desc: Some("Primary NIC".to_string()),
                lldp_mgmt_addr: docker_host
                    .map(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 20, 20))),
                lldp_sys_desc: Some("Debian 12".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "unifi-usw-48".to_string(),
            source_if_index: 5,
            target_host_name: "docker-prod01".to_string(),
            target_if_index: 1,
        });

        // Port 6 ↔ unifi-ap-lobby (deferred via NeighborUpdate)
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 6,
                if_descr: "Port 1/0/6".to_string(),
                if_name: None,
                if_alias: Some("UniFi AP".to_string()),
                if_type: 6,
                speed_bps: Some(1_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xfc, 0xec, 0xda, 0x10, 0x03, 0x06])),
                ip_address_id: None,
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress("fc:ec:da:aa:bb:01".to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("eth0".to_string())),
                lldp_sys_name: Some("unifi-ap-lobby".to_string()),
                lldp_port_desc: Some("Ethernet".to_string()),
                lldp_mgmt_addr: ap_host
                    .map(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 30, 100))),
                lldp_sys_desc: Some("UniFi AP U6-Pro".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 1),
                vlan_ids: find_vlans(network.id, &[10, 20, 30, 100]),
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "unifi-usw-48".to_string(),
            source_if_index: 6,
            target_host_name: "unifi-ap-lobby".to_string(),
            target_if_index: 1,
        });

        // Ports 7-48 — empty/down
        for port_num in 7..=48 {
            interfaces.push(Interface {
                valid_from: now,
                valid_to: None,
                lineage_id: None,
                last_seen_at: now,
                last_discovery_id: None,
                first_discovery_id: None,
                id: Uuid::new_v4(),
                created_at: now,
                updated_at: now,
                base: InterfaceBase {
                    host_id: host.id,
                    network_id: network.id,
                    if_index: port_num,
                    if_descr: format!("Port 1/0/{}", port_num),
                    if_name: None,
                    if_alias: None,
                    if_type: 6,
                    speed_bps: Some(1_000_000_000),
                    admin_status: IfAdminStatus::Up,
                    oper_status: IfOperStatus::Down,
                    mac_address: Some(MacAddress::new([
                        0xfc,
                        0xec,
                        0xda,
                        0x10,
                        0x03,
                        port_num as u8,
                    ])),
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
                },
            });
        }
    }

    // ========================================================================
    // HQ: unifi-ap-lobby — single Interface for LLDP neighbor with switch port 6
    // ========================================================================
    if let Some(host) = find_host("unifi-ap-lobby") {
        let network = networks
            .iter()
            .find(|n| n.id == host.base.network_id)
            .unwrap();
        let ip_address = find_ip_address(host.id);

        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 1,
                if_descr: "eth0".to_string(),
                if_name: None,
                if_alias: Some("Ethernet".to_string()),
                if_type: 6,
                speed_bps: Some(1_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xfc, 0xec, 0xda, 0x30, 0x23, 0x10])),
                ip_address_id: ip_address.map(|i| i.id),
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress(hq_switch_mac.to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("Port 1/0/6".to_string())),
                lldp_sys_name: Some("unifi-usw-48".to_string()),
                lldp_port_desc: Some("Port 6 - UniFi AP".to_string()),
                lldp_mgmt_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 3))),
                lldp_sys_desc: Some("UniFi USW-48-PoE".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 1),
                vlan_ids: find_vlans(network.id, &[10, 20, 30, 100]),
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "unifi-ap-lobby".to_string(),
            source_if_index: 1,
            target_host_name: "unifi-usw-48".to_string(),
            target_if_index: 6,
        });
    }

    // ========================================================================
    // DC: dc-fw01 — connected to DC switch port 1
    // ========================================================================
    if let Some(host) = find_host("dc-fw01") {
        let network = networks
            .iter()
            .find(|n| n.id == host.base.network_id)
            .unwrap();
        let ip_address = find_ip_address(host.id);

        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 1,
                if_descr: "port1".to_string(),
                if_name: None,
                if_alias: Some("LAN".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0x70, 0x4c, 0xa5, 0xdc, 0x01, 0x10])),
                ip_address_id: ip_address.map(|i| i.id),
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress(dc_switch_mac.to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("Port 1/0/1".to_string())),
                lldp_sys_name: Some("dc-switch-01".to_string()),
                lldp_port_desc: Some("Port 1 - Firewall uplink".to_string()),
                lldp_mgmt_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 2))),
                lldp_sys_desc: Some("Managed Switch".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 1),
                vlan_ids: find_vlans(network.id, &[10, 20, 30, 100]),
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "dc-fw01".to_string(),
            source_if_index: 1,
            target_host_name: "dc-switch-01".to_string(),
            target_if_index: 1,
        });
    }

    // ========================================================================
    // DC: dc-proxmox-hv01 — connected to DC switch port 2
    // ========================================================================
    if let Some(host) = find_host("dc-proxmox-hv01") {
        let network = networks
            .iter()
            .find(|n| n.id == host.base.network_id)
            .unwrap();
        let ip_address = find_ip_address(host.id);

        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 1,
                if_descr: "eno1".to_string(),
                if_name: None,
                if_alias: Some("Primary NIC".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xf8, 0xbc, 0x12, 0xdc, 0x07, 0x10])),
                ip_address_id: ip_address.map(|i| i.id),
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress(dc_switch_mac.to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("Port 1/0/2".to_string())),
                lldp_sys_name: Some("dc-switch-01".to_string()),
                lldp_port_desc: Some("Port 2 - Proxmox uplink".to_string()),
                lldp_mgmt_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 2))),
                lldp_sys_desc: Some("Managed Switch".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "dc-proxmox-hv01".to_string(),
            source_if_index: 1,
            target_host_name: "dc-switch-01".to_string(),
            target_if_index: 2,
        });
    }

    // ========================================================================
    // DC: dc-docker01 — connected to DC switch port 3
    // ========================================================================
    if let Some(host) = find_host("dc-docker01") {
        let network = networks
            .iter()
            .find(|n| n.id == host.base.network_id)
            .unwrap();
        let ip_address = find_ip_address(host.id);

        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 1,
                if_descr: "eth0".to_string(),
                if_name: None,
                if_alias: Some("Primary NIC".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xf8, 0xbc, 0x12, 0xdc, 0x11, 0x10])),
                ip_address_id: ip_address.map(|i| i.id),
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress(dc_switch_mac.to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("Port 1/0/3".to_string())),
                lldp_sys_name: Some("dc-switch-01".to_string()),
                lldp_port_desc: Some("Port 3 - Docker host uplink".to_string()),
                lldp_mgmt_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 2))),
                lldp_sys_desc: Some("Managed Switch".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "dc-docker01".to_string(),
            source_if_index: 1,
            target_host_name: "dc-switch-01".to_string(),
            target_if_index: 3,
        });
    }

    // ========================================================================
    // DC: haproxy-lb01 — connected to DC switch port 4
    // ========================================================================
    if let Some(host) = find_host("haproxy-lb01") {
        let network = networks
            .iter()
            .find(|n| n.id == host.base.network_id)
            .unwrap();
        let ip_address = find_ip_address(host.id);

        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 1,
                if_descr: "eth0".to_string(),
                if_name: None,
                if_alias: Some("Primary NIC".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0xf8, 0xbc, 0x12, 0xdc, 0x04, 0x10])),
                ip_address_id: ip_address.map(|i| i.id),
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress(dc_switch_mac.to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("Port 1/0/4".to_string())),
                lldp_sys_name: Some("dc-switch-01".to_string()),
                lldp_port_desc: Some("Port 4 - HAProxy uplink".to_string()),
                lldp_mgmt_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 2))),
                lldp_sys_desc: Some("Managed Switch".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "haproxy-lb01".to_string(),
            source_if_index: 1,
            target_host_name: "dc-switch-01".to_string(),
            target_if_index: 4,
        });
    }

    // ========================================================================
    // DC Switch — dc-switch-01 (24 ports)
    // ========================================================================
    if let Some(host) = find_host("dc-switch-01") {
        let network = networks
            .iter()
            .find(|n| n.id == host.base.network_id)
            .unwrap();
        let ip_address = find_ip_address(host.id);

        let dc_fw = find_host("dc-fw01");
        let dc_proxmox = find_host("dc-proxmox-hv01");
        let dc_docker = find_host("dc-docker01");
        let dc_haproxy = find_host("haproxy-lb01");

        // Port 1 ↔ dc-fw01
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 1,
                if_descr: "Port 1/0/1".to_string(),
                if_name: None,
                if_alias: Some("Firewall uplink".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0x00, 0x1c, 0x73, 0xdc, 0x02, 0x01])),
                ip_address_id: ip_address.map(|i| i.id),
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress("a0:36:9f:11:22:01".to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("port1".to_string())),
                lldp_sys_name: Some("dc-fw01".to_string()),
                lldp_port_desc: Some("LAN".to_string()),
                lldp_mgmt_addr: dc_fw
                    .map(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 1))),
                lldp_sys_desc: Some("FortiGate-100F".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 1),
                vlan_ids: find_vlans(network.id, &[10, 20, 30, 100]),
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "dc-switch-01".to_string(),
            source_if_index: 1,
            target_host_name: "dc-fw01".to_string(),
            target_if_index: 1,
        });

        // Port 2 ↔ dc-proxmox-hv01
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 2,
                if_descr: "Port 1/0/2".to_string(),
                if_name: None,
                if_alias: Some("Proxmox uplink".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0x00, 0x1c, 0x73, 0xdc, 0x02, 0x02])),
                ip_address_id: None,
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress("d4:be:d9:aa:bb:01".to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("eno1".to_string())),
                lldp_sys_name: Some("dc-proxmox-hv01".to_string()),
                lldp_port_desc: Some("Primary NIC".to_string()),
                lldp_mgmt_addr: dc_proxmox
                    .map(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 10, 5))),
                lldp_sys_desc: Some("Proxmox VE 8.1".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "dc-switch-01".to_string(),
            source_if_index: 2,
            target_host_name: "dc-proxmox-hv01".to_string(),
            target_if_index: 1,
        });

        // Port 3 ↔ dc-docker01
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 3,
                if_descr: "Port 1/0/3".to_string(),
                if_name: None,
                if_alias: Some("Docker host uplink".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0x00, 0x1c, 0x73, 0xdc, 0x02, 0x03])),
                ip_address_id: None,
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress("aa:bb:cc:dd:ee:02".to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("eth0".to_string())),
                lldp_sys_name: Some("dc-docker01".to_string()),
                lldp_port_desc: Some("Primary NIC".to_string()),
                lldp_mgmt_addr: dc_docker
                    .map(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 10, 20))),
                lldp_sys_desc: Some("Debian 12".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "dc-switch-01".to_string(),
            source_if_index: 3,
            target_host_name: "dc-docker01".to_string(),
            target_if_index: 1,
        });

        // Port 4 ↔ haproxy-lb01
        interfaces.push(Interface {
            valid_from: now,
            valid_to: None,
            lineage_id: None,
            last_seen_at: now,
            last_discovery_id: None,
            first_discovery_id: None,
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: InterfaceBase {
                host_id: host.id,
                network_id: network.id,
                if_index: 4,
                if_descr: "Port 1/0/4".to_string(),
                if_name: None,
                if_alias: Some("HAProxy uplink".to_string()),
                if_type: 6,
                speed_bps: Some(10_000_000_000),
                admin_status: IfAdminStatus::Up,
                oper_status: IfOperStatus::Up,
                mac_address: Some(MacAddress::new([0x00, 0x1c, 0x73, 0xdc, 0x02, 0x04])),
                ip_address_id: None,
                neighbor: None,
                neighbor_seen_at: None,
                lldp_chassis_id: Some(LldpChassisId::MacAddress("11:22:33:44:55:01".to_string())),
                lldp_port_id: Some(LldpPortId::InterfaceName("eth0".to_string())),
                lldp_sys_name: Some("haproxy-lb01".to_string()),
                lldp_port_desc: Some("Primary NIC".to_string()),
                lldp_mgmt_addr: dc_haproxy
                    .map(|_| std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 30, 10))),
                lldp_sys_desc: Some("HAProxy 2.8".to_string()),
                cdp_device_id: None,
                cdp_port_id: None,
                cdp_platform: None,
                cdp_address: None,
                fdb_macs: None,
                native_vlan_id: find_vlan(network.id, 20),
                vlan_ids: None,
            },
        });
        neighbor_updates.push(NeighborUpdate {
            source_host_name: "dc-switch-01".to_string(),
            source_if_index: 4,
            target_host_name: "haproxy-lb01".to_string(),
            target_if_index: 1,
        });

        // Ports 5-24 — empty/down
        for port_num in 5..=24 {
            interfaces.push(Interface {
                valid_from: now,
                valid_to: None,
                lineage_id: None,
                last_seen_at: now,
                last_discovery_id: None,
                first_discovery_id: None,
                id: Uuid::new_v4(),
                created_at: now,
                updated_at: now,
                base: InterfaceBase {
                    host_id: host.id,
                    network_id: network.id,
                    if_index: port_num,
                    if_descr: format!("Port 1/0/{}", port_num),
                    if_name: None,
                    if_alias: None,
                    if_type: 6,
                    speed_bps: Some(1_000_000_000),
                    admin_status: IfAdminStatus::Up,
                    oper_status: IfOperStatus::Down,
                    mac_address: Some(MacAddress::new([
                        0x00,
                        0x1c,
                        0x73,
                        0xdc,
                        0x02,
                        port_num as u8,
                    ])),
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
                },
            });
        }
    }

    (interfaces, neighbor_updates)
}

// ============================================================================
// Daemons
// ============================================================================

fn generate_daemons(
    networks: &[Network],
    hosts: &[&Host],
    _subnets: &[Subnet],
    now: DateTime<Utc>,
    user_id: Uuid,
) -> Vec<Daemon> {
    let find_network = |name: &str| {
        networks
            .iter()
            .find(|n| n.base.name.contains(name))
            .unwrap()
    };
    let find_host = |name: &str| hosts.iter().find(|h| h.base.name == name).copied();

    let mut daemons = Vec::new();

    // HQ Daemon on docker-prod01. (Interfaced subnets are populated at runtime from
    // daemon heartbeats into the `daemon_interfaced_subnets` junction; demo seed data
    // leaves them empty.)
    if let Some(host) = find_host("docker-prod01") {
        let network = find_network("Headquarters");
        daemons.push(Daemon {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: DaemonBase {
                host_id: host.id,
                network_id: network.id,
                url: "https://docker-prod01.acme.local:8443".to_string(),
                last_seen: Some(now),
                mode: DaemonMode::DaemonPoll,
                name: "HQ Daemon".to_string(),
                tags: vec![],
                version: Version::parse(env!("CARGO_PKG_VERSION"))
                    .map(Some)
                    .unwrap_or_default(),
                user_id,
                api_key_id: None,
                is_unreachable: false,
                standby: false,
                standby_cleared_at: None,
            },
        });
    }

    // DC Daemon on dc-docker01
    if let Some(host) = find_host("dc-docker01") {
        let network = find_network("Data Center");
        daemons.push(Daemon {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: DaemonBase {
                host_id: host.id,
                network_id: network.id,
                url: "https://docker01.dc.acme.io:8443".to_string(),
                last_seen: Some(now),
                mode: DaemonMode::DaemonPoll,
                standby_cleared_at: None,
                name: "DC Daemon".to_string(),
                tags: vec![],
                version: Version::parse(env!("CARGO_PKG_VERSION"))
                    .map(Some)
                    .unwrap_or_default(),
                user_id,
                api_key_id: None,
                is_unreachable: false,
                standby: false,
            },
        });
    }

    daemons
}

// ============================================================================
// API Keys
// ============================================================================

fn generate_api_keys(networks: &[Network], now: DateTime<Utc>) -> Vec<DaemonApiKey> {
    let find_network = |name: &str| {
        networks
            .iter()
            .find(|n| n.base.name.contains(name))
            .unwrap()
    };

    vec![
        DaemonApiKey {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: DaemonApiKeyBase {
                key: format!("demo_hq_{}", Uuid::new_v4().simple()),
                name: "HQ Daemon Key".to_string(),
                last_used: Some(now),
                expires_at: None,
                network_id: find_network("Headquarters").id,
                is_enabled: true,
                tags: vec![],
                daemon_id: None,
                plaintext: None,
            },
        },
        DaemonApiKey {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: DaemonApiKeyBase {
                key: format!("demo_dc_{}", Uuid::new_v4().simple()),
                name: "DC Daemon Key".to_string(),
                last_used: Some(now),
                expires_at: None,
                network_id: find_network("Data Center").id,
                is_enabled: true,
                tags: vec![],
                daemon_id: None,
                plaintext: None,
            },
        },
    ]
}

// ============================================================================
// Discoveries
// ============================================================================

fn generate_discoveries(
    networks: &[Network],
    subnets: &[Subnet],
    daemons: &[Daemon],
    _hosts: &[&Host],
    credentials: &[Credential],
    now: DateTime<Utc>,
) -> Vec<Discovery> {
    let find_network = |name: &str| {
        networks
            .iter()
            .find(|n| n.base.name.contains(name))
            .unwrap()
    };
    let find_daemon = |name: &str| daemons.iter().find(|d| d.base.name.contains(name));
    let find_subnets_for_network = |network_id: Uuid| -> Vec<Uuid> {
        subnets
            .iter()
            .filter(|s| s.base.network_id == network_id)
            .map(|s| s.id)
            .collect()
    };

    // Credential IDs for integration targets.
    let default_snmp_cred_id = credentials
        .iter()
        .find(|c| c.base.name == "Default SNMPv2c")
        .unwrap()
        .id;
    let network_devices_cred_id = credentials
        .iter()
        .find(|c| c.base.name == "Network Devices")
        .unwrap()
        .id;
    let docker_proxy_cred_id = credentials
        .iter()
        .find(|c| c.base.name == "Docker TLS Proxy")
        .unwrap()
        .id;

    // Both SNMP creds are broadcast to every network (see
    // `generate_network_credential_assignments`), so every discovery targets both.
    let snmp_network_targets = || {
        vec![
            IntegrationTarget::Network {
                credential_id: default_snmp_cred_id,
            },
            IntegrationTarget::Network {
                credential_id: network_devices_cred_id,
            },
        ]
    };
    // Ad-hoc discoveries additionally reach the daemon-local Docker socket.
    let snmp_and_docker_targets = || {
        let mut targets = snmp_network_targets();
        targets.push(IntegrationTarget::DaemonHost {
            credential_id: docker_proxy_cred_id,
        });
        targets
    };

    let unified = |daemon: &Daemon, subnet_ids: Option<Vec<Uuid>>| DiscoveryType::Unified {
        host_id: daemon.base.host_id,
        subnet_ids,
        host_naming_fallback: HostNamingFallback::BestService,
        scan_settings: ScanSettings::default(),
    };

    let mut discoveries = Vec::new();

    // ===== HQ Unified discovery =====
    let hq = find_network("Headquarters");
    if let Some(daemon) = find_daemon("HQ") {
        let hq_subnet_ids = find_subnets_for_network(hq.id);
        discoveries.push(Discovery {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: DiscoveryBase {
                discovery_type: unified(daemon, Some(hq_subnet_ids.clone())),
                run_type: RunType::AdHoc {
                    last_run: Some(now - Duration::days(2)),
                },
                name: "Discovery".to_string(),
                daemon_id: daemon.id,
                network_id: hq.id,
                tags: vec![],
            },
            scan_count: 0,
            force_full_scan: false,
            integration_targets: snmp_and_docker_targets(),
        });

        // Historical — completed 3 weeks ago
        let three_weeks_ago = now - Duration::weeks(3);
        let hq_unified = unified(daemon, Some(hq_subnet_ids.clone()));
        discoveries.push(Discovery {
            id: Uuid::new_v4(),
            created_at: three_weeks_ago,
            updated_at: three_weeks_ago,
            base: DiscoveryBase {
                discovery_type: hq_unified.clone(),
                run_type: RunType::Historical {
                    results: Box::new(DiscoveryUpdatePayload {
                        session_id: Uuid::new_v4(),
                        daemon_id: daemon.id,
                        network_id: hq.id,
                        phase: DiscoveryPhase::Complete,
                        discovery_type: hq_unified.clone(),
                        progress: 100,
                        error: None,
                        warnings: Vec::new(),
                        started_at: Some(three_weeks_ago),
                        finished_at: Some(three_weeks_ago + Duration::minutes(12)),
                        hosts_discovered: None,
                        estimated_remaining_secs: None,
                        discovery_id: None,
                        scanned: None,
                    }),
                },
                name: "Discovery".to_string(),
                daemon_id: daemon.id,
                network_id: hq.id,
                tags: vec![],
            },
            scan_count: 0,
            force_full_scan: false,
            integration_targets: snmp_network_targets(),
        });

        // Historical — completed 1 week ago
        let one_week_ago = now - Duration::weeks(1);
        discoveries.push(Discovery {
            id: Uuid::new_v4(),
            created_at: one_week_ago,
            updated_at: one_week_ago,
            base: DiscoveryBase {
                discovery_type: hq_unified.clone(),
                run_type: RunType::Historical {
                    results: Box::new(DiscoveryUpdatePayload {
                        session_id: Uuid::new_v4(),
                        daemon_id: daemon.id,
                        network_id: hq.id,
                        phase: DiscoveryPhase::Complete,
                        discovery_type: hq_unified,
                        progress: 100,
                        error: None,
                        warnings: Vec::new(),
                        started_at: Some(one_week_ago),
                        finished_at: Some(one_week_ago + Duration::minutes(8)),
                        hosts_discovered: None,
                        estimated_remaining_secs: None,
                        discovery_id: None,
                        scanned: None,
                    }),
                },
                name: "Discovery".to_string(),
                daemon_id: daemon.id,
                network_id: hq.id,
                tags: vec![],
            },
            scan_count: 0,
            force_full_scan: false,
            integration_targets: snmp_network_targets(),
        });
    }

    // ===== DC Unified discovery =====
    let dc = find_network("Data Center");
    if let Some(daemon) = find_daemon("DC") {
        let dc_subnet_ids = find_subnets_for_network(dc.id);
        discoveries.push(Discovery {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: DiscoveryBase {
                discovery_type: unified(daemon, Some(dc_subnet_ids.clone())),
                run_type: RunType::AdHoc {
                    last_run: Some(now - Duration::days(3)),
                },
                name: "Discovery".to_string(),
                daemon_id: daemon.id,
                network_id: dc.id,
                tags: vec![],
            },
            scan_count: 0,
            force_full_scan: false,
            integration_targets: snmp_and_docker_targets(),
        });

        // Historical — failed 2 weeks ago
        let two_weeks_ago = now - Duration::weeks(2);
        let dc_unified = unified(daemon, Some(dc_subnet_ids));
        discoveries.push(Discovery {
            id: Uuid::new_v4(),
            created_at: two_weeks_ago,
            updated_at: two_weeks_ago,
            base: DiscoveryBase {
                discovery_type: dc_unified.clone(),
                run_type: RunType::Historical {
                    results: Box::new(DiscoveryUpdatePayload {
                        session_id: Uuid::new_v4(),
                        daemon_id: daemon.id,
                        network_id: dc.id,
                        phase: DiscoveryPhase::Failed,
                        discovery_type: dc_unified,
                        progress: 100,
                        error: Some("Connection timeout: daemon lost connectivity to subnet 172.16.20.0/24 during scan".to_string()),
                        warnings: Vec::new(),
                        started_at: Some(two_weeks_ago),
                        finished_at: Some(two_weeks_ago + Duration::minutes(3)),
                        hosts_discovered: None,
                        estimated_remaining_secs: None,
                        discovery_id: None,
                        scanned: None,
                    }),
                },
                name: "Discovery".to_string(),
                daemon_id: daemon.id,
                network_id: dc.id,
                tags: vec![],
            },
            scan_count: 0,
            force_full_scan: false,
            integration_targets: snmp_network_targets(),
        });
    }

    discoveries
}

// ============================================================================
// Shares
// ============================================================================

fn generate_shares(
    topologies: &[Topology],
    networks: &[Network],
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Vec<Share> {
    let hq_network = networks.iter().find(|n| n.base.name == "Headquarters");
    let hq_topology =
        hq_network.and_then(|net| topologies.iter().find(|t| t.base.network_id == net.id));

    let mut shares = Vec::new();

    if let (Some(network), Some(topology)) = (hq_network, hq_topology) {
        if let Ok(id) = Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890") {
            shares.push(Share {
                // Fixed UUID for demo share — used in onboarding embed
                id,
                created_at: now,
                updated_at: now,
                base: ShareBase {
                    topology_id: topology.id,
                    network_id: network.id,
                    created_by: user_id,
                    name: "HQ Public View".to_string(),
                    is_enabled: true,
                    expires_at: None,
                    password_hash: None,
                    password: None,
                    allowed_domains: None,
                    options: ShareOptions {
                        show_inspect_panel: false,
                        show_zoom_controls: false,
                        show_export_button: false,
                        show_minimap: false,
                    },
                    enabled_views: None,
                },
            });
        }

        if let Ok(id) = Uuid::parse_str("b1b2c3d4-e5f6-7890-abcd-ef1234567890") {
            shares.push(Share {
                // Fixed UUID for demo share — used on website
                id,
                created_at: now,
                updated_at: now,
                base: ShareBase {
                    topology_id: topology.id,
                    network_id: network.id,
                    created_by: user_id,
                    name: "HQ Public View - With Inspect Panel".to_string(),
                    is_enabled: true,
                    expires_at: None,
                    password_hash: None,
                    password: None,
                    allowed_domains: None,
                    options: ShareOptions {
                        show_inspect_panel: true,
                        show_zoom_controls: false,
                        show_export_button: false,
                        show_minimap: false,
                    },
                    enabled_views: None,
                },
            });
        }
    }

    shares
}

// ============================================================================
// User API Keys
// ============================================================================

fn generate_user_api_keys(
    networks: &[Network],
    organization_id: Uuid,
    now: DateTime<Utc>,
) -> Vec<(UserApiKey, Vec<Uuid>)> {
    use super::handlers::DEMO_USER_ID;

    let network_ids: Vec<Uuid> = networks.iter().map(|n| n.id).collect();
    let (_plaintext, hashed) = generate_api_key_for_storage(ApiKeyType::User);

    vec![(
        UserApiKey {
            id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            base: UserApiKeyBase {
                key: hashed,
                name: "Monitoring Integration Key".to_string(),
                user_id: DEMO_USER_ID,
                organization_id,
                permissions: UserOrgPermissions::Member,
                last_used: None,
                expires_at: None,
                is_enabled: true,
                tags: vec![],
                network_ids: vec![], // hydrated by create_with_networks
            },
        },
        network_ids,
    )]
}

// ============================================================================
// Dependencies
// ============================================================================

/// Generate demo dependencies with pre-generated service IDs for member wiring.
#[allow(clippy::vec_init_then_push)]
fn generate_dependencies(
    networks: &[Network],
    tags: &[Tag],
    svc_ids: &DependencyServiceIds,
) -> Vec<Dependency> {
    let now = Utc::now();
    let hq = networks
        .iter()
        .find(|n| n.base.name == "Headquarters")
        .unwrap();
    let dc = networks
        .iter()
        .find(|n| n.base.name == "Data Center")
        .unwrap();

    let monitoring_tag = tags
        .iter()
        .find(|t| t.base.name == "Monitoring")
        .map(|t| t.id);

    let mut dependencies = Vec::new();

    // ===== HQ Dependencies (3) =====

    // 1. Monitoring Stack: Prometheus (hub) ↔ Grafana, Uptime Kuma (spokes)
    dependencies.push(Dependency {
        valid_from: now,
        valid_to: None,
        lineage_id: None,
        id: Uuid::new_v4(),
        created_at: now,
        updated_at: now,
        base: DependencyBase {
            name: "Monitoring Stack".to_string(),
            network_id: hq.id,
            description: Some(
                "Prometheus metrics collection with Grafana visualization".to_string(),
            ),
            dependency_type: DependencyType::HubAndSpoke,
            members: DependencyMembers::Services {
                service_ids: vec![
                    svc_ids.prometheus_hq,
                    svc_ids.grafana_hq,
                    svc_ids.uptime_kuma,
                ],
            },
            source: EntitySource::Manual,
            color: Color::Purple,
            edge_style: EdgeStyle::Straight,
            tags: monitoring_tag.into_iter().collect(),
        },
    });

    // 2. Backup Flow: Proxmox VE (hv01) → TrueNAS
    dependencies.push(Dependency {
        valid_from: now,
        valid_to: None,
        lineage_id: None,
        id: Uuid::new_v4(),
        created_at: now,
        updated_at: now,
        base: DependencyBase {
            name: "Backup Flow".to_string(),
            network_id: hq.id,
            description: Some("Server backup targets to TrueNAS storage".to_string()),
            dependency_type: DependencyType::RequestPath,
            members: DependencyMembers::Bindings {
                binding_ids: vec![svc_ids.pve_hq1_binding, svc_ids.truenas_binding],
            },
            source: EntitySource::Manual,
            color: Color::Green,
            edge_style: EdgeStyle::SmoothStep,
            tags: vec![],
        },
    });

    // 3. Reverse Proxy Path: Traefik → Gitea
    dependencies.push(Dependency {
        valid_from: now,
        valid_to: None,
        lineage_id: None,
        id: Uuid::new_v4(),
        created_at: now,
        updated_at: now,
        base: DependencyBase {
            name: "Reverse Proxy Path".to_string(),
            network_id: hq.id,
            description: Some("Traffic path through reverse proxy to code hosting".to_string()),
            dependency_type: DependencyType::RequestPath,
            members: DependencyMembers::Bindings {
                binding_ids: vec![svc_ids.traefik_hq_binding, svc_ids.gitea_hq_binding],
            },
            source: EntitySource::Manual,
            color: Color::Cyan,
            edge_style: EdgeStyle::Bezier,
            tags: vec![],
        },
    });

    // ===== DC Dependencies (3) =====

    // 4. Web Traffic Flow: HAProxy → Tomcat → MariaDB
    dependencies.push(Dependency {
        valid_from: now,
        valid_to: None,
        lineage_id: None,
        id: Uuid::new_v4(),
        created_at: now,
        updated_at: now,
        base: DependencyBase {
            name: "Web Traffic Flow".to_string(),
            network_id: dc.id,
            description: Some(
                "Production web request path from load balancer through app servers to database"
                    .to_string(),
            ),
            dependency_type: DependencyType::RequestPath,
            members: DependencyMembers::Bindings {
                binding_ids: vec![
                    svc_ids.haproxy_dc_binding,
                    svc_ids.app01_dc_binding,
                    svc_ids.mariadb_dc_binding,
                ],
            },
            source: EntitySource::Manual,
            color: Color::Blue,
            edge_style: EdgeStyle::Bezier,
            tags: vec![],
        },
    });

    // 5. Observability Stack: Prometheus (container) → Grafana (container), Jaeger (container)
    dependencies.push(Dependency {
        valid_from: now,
        valid_to: None,
        lineage_id: None,
        id: Uuid::new_v4(),
        created_at: now,
        updated_at: now,
        base: DependencyBase {
            name: "Observability Stack".to_string(),
            network_id: dc.id,
            description: Some(
                "Containerized observability: Prometheus, Grafana, and Jaeger".to_string(),
            ),
            dependency_type: DependencyType::HubAndSpoke,
            members: DependencyMembers::Services {
                service_ids: vec![svc_ids.prometheus_dc, svc_ids.grafana_dc, svc_ids.jaeger_dc],
            },
            source: EntitySource::Manual,
            color: Color::Purple,
            edge_style: EdgeStyle::Straight,
            tags: monitoring_tag.into_iter().collect(),
        },
    });

    // 6. Storage Tier: MinIO → Ceph, Elasticsearch
    dependencies.push(Dependency {
        valid_from: now,
        valid_to: None,
        lineage_id: None,
        id: Uuid::new_v4(),
        created_at: now,
        updated_at: now,
        base: DependencyBase {
            name: "Storage Tier".to_string(),
            network_id: dc.id,
            description: Some("Object storage, distributed storage, and search".to_string()),
            dependency_type: DependencyType::HubAndSpoke,
            members: DependencyMembers::Services {
                service_ids: vec![svc_ids.minio_dc, svc_ids.ceph_dc, svc_ids.elasticsearch_dc],
            },
            source: EntitySource::Manual,
            color: Color::Orange,
            edge_style: EdgeStyle::SmoothStep,
            tags: vec![],
        },
    });

    dependencies
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn subnet_vlan_records_are_derived_and_reference_valid_entities() {
        let demo = DemoData::generate(Uuid::new_v4(), Uuid::new_v4());

        // The derivation should link at least the subnets whose hosts carry a
        // native VLAN (otherwise the junction is silently empty and demo
        // subnets show no VLANs).
        assert!(
            !demo.subnet_vlan_records.is_empty(),
            "expected derived subnet↔vlan links"
        );

        let subnet_ids: HashSet<Uuid> = demo.subnets.iter().map(|s| s.id).collect();
        let vlan_ids: HashSet<Uuid> = demo.vlans.iter().map(|v| v.id).collect();
        let mut pairs: HashSet<(Uuid, Uuid)> = HashSet::new();
        for r in &demo.subnet_vlan_records {
            assert!(
                subnet_ids.contains(&r.base.subnet_id),
                "subnet_vlan references unknown subnet"
            );
            assert!(
                vlan_ids.contains(&r.base.vlan_id),
                "subnet_vlan references unknown vlan"
            );
            assert!(
                pairs.insert((r.base.subnet_id, r.base.vlan_id)),
                "duplicate subnet↔vlan link"
            );
        }
    }
}
