use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::server::{
    hosts::r#impl::{
        base::{Host, HostBase},
        name::HostName,
        virtualization::HostVirtualization,
    },
    shared::{
        entities::EntityDiscriminants,
        entity_metadata::EntityCategory,
        storage::{
            snapshot::{DiscoveryTracked, Snapshotable},
            traits::{Entity, SqlValue, Storable},
        },
        types::entities::EntitySource,
    },
};

/// CSV row representation for Host export
#[derive(Serialize)]
pub struct HostCsvRow {
    pub id: Uuid,
    pub name: String,
    pub hostname: Option<String>,
    pub description: Option<String>,
    pub network_id: Uuid,
    pub source: String,
    pub hidden: bool,
    // Everything the device reported about itself. Field order is column order — headers are
    // derived from these names — so the two timestamps stay last, as they are on every other
    // CsvRow.
    pub sys_descr: Option<String>,
    pub sys_object_id: Option<String>,
    pub sys_location: Option<String>,
    pub sys_contact: Option<String>,
    pub management_url: Option<String>,
    pub chassis_id: Option<String>,
    pub sys_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Storable for Host {
    type BaseData = HostBase;

    fn table_name() -> &'static str {
        "hosts"
    }

    /// Spans what an operator actually types when hunting for a host: its
    /// name/hostname, a snippet of its description, an IP, or the name of
    /// something running on it.
    ///
    /// Children are matched with `EXISTS` rather than a JOIN so a host with
    /// many IPs or services is not duplicated in the result set — which would
    /// also corrupt the paginated `COUNT(*)`. The `valid_to IS NULL` guards
    /// keep closed SCD2 copies from matching, so a host stops being findable
    /// by an IP it no longer holds.
    fn search_predicates() -> &'static [&'static str] {
        &[
            "hosts.name ILIKE {}",
            "hosts.hostname ILIKE {}",
            "hosts.description ILIKE {}",
            "EXISTS (SELECT 1 FROM ip_addresses ia WHERE ia.host_id = hosts.id \
             AND ia.valid_to IS NULL AND host(ia.ip_address) ILIKE {})",
            "EXISTS (SELECT 1 FROM services s WHERE s.host_id = hosts.id \
             AND s.valid_to IS NULL AND s.name ILIKE {})",
        ]
    }

    const HAS_SCD2: bool = true;

    fn is_live_row(&self) -> bool {
        self.valid_to.is_none()
    }

    fn new(base: Self::BaseData) -> Self {
        let now = chrono::Utc::now();
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

    fn get_base(&self) -> Self::BaseData {
        self.base.clone()
    }

    fn to_params(&self) -> Result<(Vec<&'static str>, Vec<SqlValue>), anyhow::Error> {
        // Exhaustive destructuring ensures compile error if HostBase changes
        let Self {
            id,
            created_at,
            updated_at,
            valid_from,
            valid_to,
            lineage_id,
            last_seen_at,
            last_discovery_id,
            first_discovery_id,
            base:
                Self::BaseData {
                    name,
                    description,
                    hostname,
                    // Not a column: it qualifies an incoming observation of `hostname`, and the
                    // merge has already used it to decide whether this value may be written.
                    hostname_authoritative: _,
                    network_id,
                    hidden,
                    source,
                    virtualization_metadata,
                    virtualization_service_id,
                    tags: _, // Stored in entity_tags junction table
                    sys_descr,
                    sys_object_id,
                    sys_location,
                    sys_contact,
                    management_url,
                    chassis_id,
                    sys_name,
                    manufacturer,
                    model,
                    serial_number,
                    credential_assignments: _, // Stored in host_credentials junction table
                },
        } = self.clone();

        Ok((
            vec![
                "id",
                "created_at",
                "updated_at",
                "name",
                "name_source",
                "description",
                "network_id",
                "source",
                "hostname",
                "hidden",
                "virtualization_metadata",
                "virtualization_service_id",
                "sys_descr",
                "sys_object_id",
                "sys_location",
                "sys_contact",
                "management_url",
                "chassis_id",
                "sys_name",
                "manufacturer",
                "model",
                "serial_number",
                "valid_from",
                "valid_to",
                "lineage_id",
                "last_seen_at",
                "last_discovery_id",
                "first_discovery_id",
            ],
            vec![
                SqlValue::Uuid(id),
                SqlValue::Timestamp(created_at),
                SqlValue::Timestamp(updated_at),
                SqlValue::String(name.value().to_string()),
                SqlValue::HostNameSource(name.source()),
                SqlValue::OptionalString(description),
                SqlValue::Uuid(network_id),
                SqlValue::EntitySource(source),
                SqlValue::OptionalString(hostname),
                SqlValue::Bool(hidden),
                SqlValue::OptionalHostVirtualization(virtualization_metadata),
                SqlValue::OptionalUuid(virtualization_service_id),
                SqlValue::OptionalString(sys_descr),
                SqlValue::OptionalString(sys_object_id),
                SqlValue::OptionalString(sys_location),
                SqlValue::OptionalString(sys_contact),
                SqlValue::OptionalString(management_url),
                SqlValue::OptionalString(chassis_id),
                SqlValue::OptionalString(sys_name),
                SqlValue::OptionalString(manufacturer),
                SqlValue::OptionalString(model),
                SqlValue::OptionalString(serial_number),
                SqlValue::Timestamp(valid_from),
                SqlValue::OptionTimestamp(valid_to),
                SqlValue::OptionalUuid(lineage_id),
                SqlValue::Timestamp(last_seen_at),
                SqlValue::OptionalUuid(last_discovery_id),
                SqlValue::OptionalUuid(first_discovery_id),
            ],
        ))
    }

    fn from_row(row: &PgRow) -> Result<Self, anyhow::Error> {
        // Parse JSON fields safely
        let source: EntitySource =
            serde_json::from_value(row.get::<serde_json::Value, _>("source"))
                .map_err(|e| anyhow::anyhow!("Failed to deserialize source: {}", e))?;
        // virtualization_metadata is a nullable JSONB column, so decode it as Option: a SQL NULL
        // (as opposed to a JSONB 'null') must map to None rather than panic on a non-Option get.
        let virtualization_metadata: Option<HostVirtualization> =
            match row.get::<Option<serde_json::Value>, _>("virtualization_metadata") {
                Some(v) => serde_json::from_value(v).map_err(|e| {
                    anyhow::anyhow!("Failed to deserialize virtualization_metadata: {}", e)
                })?,
                None => None,
            };

        let name = HostName::from_parts(
            row.get::<String, _>("name"),
            row.get::<String, _>("name_source")
                .parse()
                .map_err(|e| anyhow::anyhow!("Failed to deserialize name_source: {}", e))?,
        );

        Ok(Host {
            id: row.get("id"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            valid_from: row.get("valid_from"),
            valid_to: row.get("valid_to"),
            lineage_id: row.get("lineage_id"),
            last_seen_at: row.get("last_seen_at"),
            last_discovery_id: row.get("last_discovery_id"),
            first_discovery_id: row.get("first_discovery_id"),
            base: HostBase {
                name,
                description: row.get("description"),
                network_id: row.get("network_id"),
                source,
                hostname: row.get("hostname"),
                // Not a column: it qualifies an incoming observation, and a stored hostname has
                // already won the field.
                hostname_authoritative: true,
                hidden: row.get("hidden"),
                virtualization_metadata,
                virtualization_service_id: row.get("virtualization_service_id"),
                tags: Vec::new(), // Hydrated from entity_tags junction table
                sys_descr: row.get("sys_descr"),
                sys_object_id: row.get("sys_object_id"),
                sys_location: row.get("sys_location"),
                sys_contact: row.get("sys_contact"),
                management_url: row.get("management_url"),
                chassis_id: row.get("chassis_id"),
                sys_name: row.get("sys_name"),
                manufacturer: row.get("manufacturer"),
                model: row.get("model"),
                serial_number: row.get("serial_number"),
                credential_assignments: Vec::new(), // Hydrated from host_credentials junction table
            },
        })
    }
}

impl Entity for Host {
    fn id(&self) -> Uuid {
        self.id
    }

    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    fn set_id(&mut self, id: Uuid) {
        self.id = id;
    }

    fn set_created_at(&mut self, time: DateTime<Utc>) {
        self.created_at = time;
    }

    type CsvRow = HostCsvRow;

    fn to_csv_row(&self) -> Self::CsvRow {
        HostCsvRow {
            id: self.id,
            name: self.base.name.to_string(),
            hostname: self.base.hostname.clone(),
            description: self.base.description.clone(),
            network_id: self.base.network_id,
            source: format!("{:?}", self.base.source),
            hidden: self.base.hidden,
            sys_descr: self.base.sys_descr.clone(),
            sys_object_id: self.base.sys_object_id.clone(),
            sys_location: self.base.sys_location.clone(),
            sys_contact: self.base.sys_contact.clone(),
            management_url: self.base.management_url.clone(),
            chassis_id: self.base.chassis_id.clone(),
            sys_name: self.base.sys_name.clone(),
            manufacturer: self.base.manufacturer.clone(),
            model: self.base.model.clone(),
            serial_number: self.base.serial_number.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    fn entity_type() -> EntityDiscriminants {
        EntityDiscriminants::Host
    }

    const ENTITY_NAME_SINGULAR: &'static str = "Host";
    const ENTITY_NAME_PLURAL: &'static str = "Hosts";
    const ENTITY_DESCRIPTION: &'static str =
        "Network hosts (devices). Manage discovered or manually created hosts on your network.";

    fn entity_category() -> EntityCategory {
        EntityCategory::NetworkInfrastructure
    }

    fn network_id(&self) -> Option<Uuid> {
        Some(self.base.network_id)
    }

    fn organization_id(&self) -> Option<Uuid> {
        None
    }

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    fn set_updated_at(&mut self, time: DateTime<Utc>) {
        self.updated_at = time;
    }

    fn get_tags(&self) -> Option<&Vec<Uuid>> {
        Some(&self.base.tags)
    }

    fn set_tags(&mut self, tags: Vec<Uuid>) {
        self.base.tags = tags;
    }

    fn set_source(&mut self, source: EntitySource) {
        self.base.source = source;
    }

    fn preserve_immutable_fields(&mut self, existing: &Self) {
        // source is set at creation time (Manual or Discovery), cannot be changed
        self.base.source = existing.base.source.clone();
        self.created_at = existing.created_at;
        self.updated_at = existing.updated_at;
    }
}

impl Snapshotable for Host {
    fn id_value(&self) -> Uuid {
        self.id
    }
    fn set_id_value(&mut self, id: Uuid) {
        self.id = id;
    }
    fn valid_from(&self) -> DateTime<Utc> {
        self.valid_from
    }
    fn valid_to(&self) -> Option<DateTime<Utc>> {
        self.valid_to
    }
    fn lineage_id(&self) -> Option<Uuid> {
        self.lineage_id
    }
    fn set_valid_from(&mut self, t: DateTime<Utc>) {
        self.valid_from = t;
    }
    fn set_valid_to(&mut self, t: Option<DateTime<Utc>>) {
        self.valid_to = t;
    }
    fn set_lineage_id(&mut self, id: Option<Uuid>) {
        self.lineage_id = id;
    }
    // Hosts are top-level — no within-tracked-set FKs to remap.
}

impl DiscoveryTracked for Host {
    // Overrides the trait default: this type carries `EntitySource`, so a
    // manually- or system-created row must never read as stale (discovery
    // never refreshes its `last_seen_at`).
    fn is_discovery_managed(&self) -> bool {
        self.base.source.is_from_discovery()
    }

    fn last_seen_at(&self) -> DateTime<Utc> {
        self.last_seen_at
    }
    fn last_discovery_id(&self) -> Option<Uuid> {
        self.last_discovery_id
    }
    fn first_discovery_id(&self) -> Option<Uuid> {
        self.first_discovery_id
    }
    fn set_last_seen_at(&mut self, t: DateTime<Utc>) {
        self.last_seen_at = t;
    }
    fn set_last_discovery_id(&mut self, id: Option<Uuid>) {
        self.last_discovery_id = id;
    }
    fn set_first_discovery_id(&mut self, id: Option<Uuid>) {
        self.first_discovery_id = id;
    }

    fn scanned_in_session_filter(
        scanned: &crate::server::daemons::r#impl::api::ScannedEntityIds,
    ) -> crate::server::shared::storage::filter::StorableFilter<Self> {
        crate::server::shared::storage::filter::StorableFilter::<Self>::new_from_uuids_column(
            "id",
            &scanned.host_ids,
        )
    }
}
