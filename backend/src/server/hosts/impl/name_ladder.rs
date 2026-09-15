//! What to call a host that has no name, and which piece of evidence supplied the answer.
//!
//! [`HostName`](super::name::HostName) decides what is *stored* in `name`. This ladder decides what a
//! host is *called*: the stored name when there is one, and otherwise the best identifying evidence
//! the host carries. The rungs below `name` are deliberately not rungs of `HostName`. Copying a
//! chassis id into `name` would duplicate a column this reads from, and it would then have to be
//! displaced when a real name arrives.
//!
//! The whole ladder is returned, not only its result, because the host editor shows every rung
//! alongside the one that won. The UI reads the order and the winner from here rather than walking
//! the rungs itself, so the title and the explanation of the title cannot disagree.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::server::hosts::r#impl::base::Host;
use crate::server::ip_addresses::r#impl::base::IPAddress;
use crate::server::shared::attribution::{self, AttributeSource};

/// One rung of the display-name ladder, highest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum HostNameRung {
    /// The host's stored name, whoever supplied it.
    Name,
    /// The hostname the host resolved to or reported.
    Hostname,
    /// SNMP `sysName`, or the same field from a controller.
    SysName,
    /// The chassis id, the one identifier an LLDP far end is known by.
    ChassisId,
    /// The host's first address, by position.
    Address,
}

/// What one rung of the ladder holds for a particular host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HostNameLadderEntry {
    pub rung: HostNameRung,
    /// The rung's value, or `None` when the host has nothing there. A value holding only
    /// whitespace counts as nothing.
    #[schema(required)]
    pub value: Option<String>,
    /// Where the value came from. `None` when there is no value, and for the rungs whose field
    /// carries no provenance (`Hostname` and `Address`).
    #[schema(required)]
    pub source: Option<AttributeSource>,
}

impl HostNameLadderEntry {
    fn new(rung: HostNameRung, value: Option<String>, source: Option<AttributeSource>) -> Self {
        let source = value.as_ref().and(source);
        Self {
            rung,
            value,
            source,
        }
    }
}

/// The value a ladder resolves to and the rung it came from: the first entry holding a value.
pub fn resolve_name_ladder(ladder: &[HostNameLadderEntry]) -> Option<(String, HostNameRung)> {
    ladder
        .iter()
        .find_map(|entry| entry.value.clone().map(|value| (value, entry.rung)))
}

impl Host {
    /// Every rung of the display-name ladder for this host, highest first.
    ///
    /// **The one place the order is written.** `host_display_name_sql!` in `base.rs` repeats it in
    /// SQL for sorting, and that copy must follow any change here.
    pub fn name_ladder<'a>(
        &self,
        addresses: impl IntoIterator<Item = &'a IPAddress>,
    ) -> [HostNameLadderEntry; 5] {
        fn non_blank(value: &str) -> Option<String> {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }

        let base = &self.base;
        [
            HostNameLadderEntry::new(
                HostNameRung::Name,
                (!base.name.is_blank()).then(|| base.name.to_string()),
                Some(base.name.source()),
            ),
            HostNameLadderEntry::new(
                HostNameRung::Hostname,
                base.hostname.as_deref().and_then(non_blank),
                None,
            ),
            HostNameLadderEntry::new(
                HostNameRung::SysName,
                attribution::text_of(&base.sys_name)
                    .as_deref()
                    .and_then(non_blank),
                base.sys_name.as_ref().map(|v| v.source()),
            ),
            HostNameLadderEntry::new(
                HostNameRung::ChassisId,
                attribution::text_of(&base.chassis_id)
                    .as_deref()
                    .and_then(non_blank),
                base.chassis_id.as_ref().map(|v| v.source()),
            ),
            HostNameLadderEntry::new(
                HostNameRung::Address,
                addresses
                    .into_iter()
                    .next()
                    .map(|ip| ip.base.ip_address.to_string()),
                None,
            ),
        ]
    }

    /// What to call this host and which rung said so. `None` when nothing identifies it.
    pub fn resolved_name<'a>(
        &self,
        addresses: impl IntoIterator<Item = &'a IPAddress>,
    ) -> Option<(String, HostNameRung)> {
        resolve_name_ladder(&self.name_ladder(addresses))
    }

    /// What to call this host: its name, or the best identifying evidence we hold when it has
    /// none.
    ///
    /// `None` rather than `Some("")` when nothing identifies it. A `HostName::Unnamed` formats as
    /// the empty string, so returning it would put a name on the host that every consumer's `??`
    /// fallback then reads as present, a row or a node titled with nothing at all. Absence has to
    /// be expressible for those fallbacks to fire.
    ///
    /// On `Host` rather than on the topology context that first needed it, because the host list
    /// and the same host drawn in topology must not disagree about what it is called. One ladder,
    /// every surface.
    pub fn display_name<'a>(
        &self,
        addresses: impl IntoIterator<Item = &'a IPAddress>,
    ) -> Option<String> {
        self.resolved_name(addresses).map(|(value, _)| value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::hosts::r#impl::attributes::HostSysNameValue;
    use crate::server::hosts::r#impl::name::{HostName, HostNameSources};
    use crate::server::services::r#impl::patterns::ClientProbe;
    use crate::server::shared::attribution::Attributed;

    /// The editor shows the evidence under a name, not only the name. A rung that lost still has
    /// to report what it holds, or a person looking at a named host could not see what the host
    /// would fall back to without it.
    #[test]
    fn a_winning_rung_leaves_the_rungs_below_it_readable() {
        let addresses = [crate::server::shared::types::examples::ip_address()];
        let mut host = crate::server::shared::types::examples::host();
        host.base.name = HostName::manual("Core Switch".to_string());
        host.base.hostname = Some("switch.lan".to_string());
        host.base.sys_name = Some(Attributed::new(
            HostSysNameValue("core-sw-01".to_string()),
            AttributeSource::Probe(ClientProbe::Snmp),
        ));
        host.base.chassis_id = None;

        let ladder = host.name_ladder(&addresses);
        let entry = |rung| ladder.iter().find(|e| e.rung == rung).unwrap();

        assert_eq!(
            resolve_name_ladder(&ladder),
            Some(("Core Switch".to_string(), HostNameRung::Name))
        );
        assert_eq!(
            entry(HostNameRung::SysName).source,
            Some(AttributeSource::Probe(ClientProbe::Snmp)),
            "a rung that lost keeps its provenance"
        );
        assert_eq!(
            entry(HostNameRung::Hostname).source,
            None,
            "a hostname carries no provenance, and the ladder must not invent one"
        );
        assert_eq!(
            entry(HostNameRung::ChassisId),
            &HostNameLadderEntry {
                rung: HostNameRung::ChassisId,
                value: None,
                source: None,
            },
            "an absent value has no source, even though the response defaults one to Unspecified"
        );
    }

    /// An unnamed host's stored name carries `Unspecified`, and the ladder must report the rung
    /// as empty rather than as an unattributed name.
    #[test]
    fn an_unnamed_host_has_an_empty_name_rung() {
        let mut host = crate::server::shared::types::examples::host();
        host.base.name = HostName::unnamed();

        let ladder = host.name_ladder(&[]);
        assert_eq!(ladder[0].rung, HostNameRung::Name);
        assert_eq!(ladder[0].value, None);
        assert_eq!(ladder[0].source, None);
    }
}
