//! The one answer to "does this row have an identity worth resolving?"
//!
//! L2 resolution asks that question in five places — the SQL that selects candidate rows, the
//! adjacency build, the guard at the top of the resolution loop, the arm that chooses which
//! identifier the ladder runs on, and the MAC-binding test that decides whether an existing
//! binding is worth re-examining — and every one of them used to spell it out by hand. Keeping
//! five hand-written copies in step failed: making a neighbour identified only by a name resolve
//! took three commits, each necessary and none sufficient, because each time the layer being
//! fixed was right and the next layer down quietly threw the result away. A fourth copy was found
//! by review, about to misjudge exactly the rows the three commits had newly made resolvable.
//!
//! Every one of those failures was silent. A row the SQL does not select cannot be counted as a
//! failure, and a row that falls past every arm of the ladder to `None` stores no neighbour *and*
//! raises no warning — so a divergence between two copies shows up as a link that is simply
//! absent, with nothing anywhere saying why.
//!
//! So the rule lives here once, as data: [`IDENTITY_COLUMNS`] has an entry per arm of the
//! resolution ladder, anchored on the column that carries that arm's identity, and holds *both*
//! readings of it — the SQL expression that yields the identifier and the Rust accessor that
//! reads the same identifier off a row in memory. Adding an arm to one reading without the other
//! is not something a reviewer has to catch; there is one list, and an entry has both halves or
//! it does not compile.
//!
//! There is a *third* reading, and it is the one that has to be asserted rather than made
//! structural: the arms themselves, written out by hand in `resolve_lldp_links` and
//! `build_neighbor_adjacency`. `every_column_in_the_list_reaches_an_arm_of_the_ladder` is what
//! stops an entry being half-adopted — admitted by the predicate, selected by the SQL, and then
//! matched by no arm, which stores no neighbour and raises no warning.
//!
//! # What counts as an identity
//!
//! Exactly the two identifiers the resolution ladder has an arm for:
//!
//! - **`lldp_chassis_id`**, run through [`LldpChassisId::resolve_host_id`]. Its identifier is the
//!   chassis id — *or*, when the chassis id is present but blank, `lldp_sys_name`, because that is
//!   the last rung of the same arm. Such a row resolves today and always has: it is selected,
//!   takes the chassis arm, finds nothing to look the chassis id up by, and is placed by
//!   `resolve_host_id`'s `sysName` fallback. Reading that fallback here is what makes this
//!   predicate the truth about the arm rather than an approximation of it. Leaving it out reads as
//!   harmless — `resolve_host_id` consults `lldp_sys_name` either way — but the consultation is
//!   reached only *through* an arm this predicate gates, so omitting it stopped those rows being
//!   selected at all: no neighbour stored, no warning raised. That is exactly the silent drop this
//!   module exists to remove, reintroduced by its own fix and caught by review.
//! - **`cdp_device_id`**, resolved against `hosts.sys_name`.
//!
//! Deliberately **not** included:
//!
//! - **`lldp_sys_name` on its own.** It is a *rung* of the chassis arm, not an arm of its own:
//!   with no chassis id present there is no `resolve_host_id` call to make, so a row admitted for
//!   its system name alone would be admitted only to fall through every arm — the failure this
//!   module is about, in the other direction. Making such a row resolve means giving the ladder an
//!   arm for it, which is its own piece of work: `decode_tlv_name` names it as what a chassis-side
//!   GH #88 guard depends on, and it is deliberately not folded in here.
//! - **`cdp_address`.** It was in the SQL filter and in the resolution guard, and in neither did
//!   it do anything: the ladder has no arm for it, so a row admitted on `cdp_address` alone fell
//!   straight through to the one failure counter no warning covers. It is where you *manage* a
//!   device, not what is on the other end of the cable, and the two are routinely different. The
//!   FDB filter and the MAC-binding test already left it out, so excluding it makes four sites
//!   agree instead of splitting two against two.
//! - **`lldp_port_id` / `lldp_port_desc` / `cdp_port_id`.** A port id names a port on a device
//!   this row cannot name, which is not an identity to resolve. They are the *second* half of a
//!   resolution, run only once a host is known.
//! - **`neighbor_interface_id` / `neighbor_host_id`.** A resolution already made is not an
//!   identity to resolve. The one filter that admits them,
//!   `StorableFilter::lldp_neighbors_in_network`, needs already-bound rows for the reciprocal
//!   tier and says so by composing `has_resolvable_identity OR already-bound` rather than by
//!   quietly adding two columns to this list.
//!
//! # Emptiness
//!
//! One rule, [`identifier_is_resolvable`], and its SQL twin [`sql_identifier_is_resolvable`]. The
//! layers used to disagree three ways — `IS NOT NULL` in SQL, `is_none()` in the guard, and
//! trimmed-non-empty further down the ladder — which let a row carrying a blank identifier be
//! selected, pass the guard, enter the ladder with nothing to look up, come back `NoStrategy`
//! (which raises no warning), and be counted in `stats.total` as though it had been judged.
//!
//! # What this is *not*
//!
//! It is not the GH #88 identifier guard. [`crate::server::lldp::usable_identifier`] answers a
//! different question — "is this string a usable identifier at all", asked of a value arriving
//! from a device at a transport boundary — and `decode_tlv_name` documents at length why it is
//! applied to port ids and deliberately not to chassis ids: a rejected port id falls to the next
//! tier, while a rejected chassis id takes the row out of resolution entirely, silently. Folding
//! that guard in here would do exactly what that comment warns against, so this predicate judges
//! only presence and emptiness, and a chassis id full of control bytes is still selected, still
//! counted, and still warned about.

use super::base::InterfaceBase;
use crate::server::lldp::LldpChassisId;
use std::borrow::Cow;

/// Turns a bare column name into one the query being built can refer to.
pub type QualifyColumn<'a> = &'a dyn Fn(&str) -> String;

/// SQL yielding one arm's identifier, given that arm's already-qualified column and a way to
/// qualify any *other* column the identifier reads.
pub type SqlIdentifier = fn(&str, QualifyColumn<'_>) -> String;

/// One column that can carry a neighbour identity, with the two readings that must never disagree.
///
/// The point of pairing them in a single value is that they cannot be maintained separately: the
/// SQL predicate and the Rust predicate are both folds over this one list, so a column reaches
/// both or neither.
pub struct IdentityColumn {
    /// The column the identity is anchored on: present, it is an identity, absent, there is none.
    pub column: &'static str,
    /// SQL yielding this arm's identifier as `text`, given [`Self::column`] already qualified and
    /// a way to qualify any *other* column the identifier depends on.
    ///
    /// Not simply the column: `lldp_chassis_id` is a JSONB tagged enum, so the identifier is the
    /// `value` inside it, falling back to `lldp_sys_name` the way the chassis arm itself does. A
    /// row holding the JSON scalar `null` — which older writes produced, see migration
    /// `20260316120000_fix_jsonb_null_if_entries` — yields SQL NULL for both members and so is
    /// judged as carrying no identifier, which is what it is.
    pub sql_identifier: SqlIdentifier,
    /// The same identifier, read off a row already in memory.
    pub identifier: for<'a> fn(&'a InterfaceBase) -> Option<Cow<'a, str>>,
}

/// Every column a neighbour identity can live in. See the module docs for what is left out and why.
pub const IDENTITY_COLUMNS: &[IdentityColumn] = &[
    IdentityColumn {
        column: "lldp_chassis_id",
        sql_identifier: sql_chassis_identifier,
        identifier: chassis_identifier,
    },
    IdentityColumn {
        column: "cdp_device_id",
        sql_identifier: sql_column_itself,
        identifier: cdp_device_identifier,
    },
];

/// The SQL twin of [`chassis_identifier`], over the row as Postgres stores it.
///
/// `->> 'value'` reads the content of the `#[serde(tag = "subtype", content = "value")]` enum;
/// `->> 'subtype'` is how "there is a chassis id here at all" is asked of a JSONB column, since a
/// stored JSON `null` is not SQL NULL and would answer `IS NOT NULL` with the wrong thing.
fn sql_chassis_identifier(chassis: &str, qualify: QualifyColumn<'_>) -> String {
    let sys_name = qualify("lldp_sys_name");
    format!(
        "coalesce(nullif(btrim({chassis} ->> 'value', {SQL_PADDING}), ''), \
         case when {chassis} ->> 'subtype' is not null then {sys_name} end)"
    )
}

/// A plain text column is its own identifier.
fn sql_column_itself(qualified_column: &str, _qualify: QualifyColumn<'_>) -> String {
    qualified_column.to_string()
}

/// What the ladder's chassis arm would actually look a row up by.
///
/// The chassis id read through [`LldpChassisId::identifier`] rather than by matching the variants
/// again here, so the string this predicate judges is byte-for-byte the string `resolve_host_id`
/// looks up — and, when that string is blank, the `lldp_sys_name` that same arm falls back to.
/// The fallback is conditioned on a chassis id being *present*: a system name with no chassis id
/// beside it has no arm to be the last rung of. See the module docs.
fn chassis_identifier(base: &InterfaceBase) -> Option<Cow<'_, str>> {
    let identifier = base.lldp_chassis_id.as_ref()?.identifier();
    if identifier_is_resolvable(&identifier) {
        return Some(Cow::Owned(identifier));
    }
    base.lldp_sys_name.as_deref().map(Cow::Borrowed)
}

fn cdp_device_identifier(base: &InterfaceBase) -> Option<Cow<'_, str>> {
    base.cdp_device_id.as_deref().map(Cow::Borrowed)
}

/// Whether an identifier has any content, and so is worth a lookup.
///
/// Padding is ASCII whitespace and nothing else, because [`sql_identifier_is_resolvable`] trims
/// exactly those five characters by name and the two must give the same answer for the same
/// bytes. `str::trim` would additionally strip U+00A0 and the other Unicode spaces, which
/// Postgres `btrim` would not — a rule with two answers depending on which layer asks is the
/// defect this module exists to remove, and a device that names itself with a non-breaking space
/// is not a case worth reintroducing it for.
pub fn identifier_is_resolvable(value: &str) -> bool {
    value.chars().any(|c| !c.is_ascii_whitespace())
}

/// The characters [`identifier_is_resolvable`] treats as padding, as a Postgres escape string.
///
/// Space, tab, line feed, carriage return and form feed: exactly the five characters
/// `char::is_ascii_whitespace` answers true for, and no more. Vertical tab (U+000B) is *not*
/// among them — Rust excludes it, so including it here would make a chassis id of a lone
/// vertical tab padding to the database and content to the server. Spelled out rather than
/// relying on `btrim`'s default (U+0020 only) or on `[[:space:]]`, whose membership depends on
/// the database's collation.
const SQL_PADDING: &str = r"E' \t\n\r\x0C'";

/// The SQL twin of [`identifier_is_resolvable`], over an expression yielding the identifier.
///
/// `coalesce` rather than three-valued logic on purpose: every clause built from this is a plain
/// boolean, so `NOT (…)` means what it reads as. Without it a NULL column would make the negation
/// used by `unresolved_fdb_in_network` NULL rather than true, and the rows that filter exists for
/// — the ones carrying no identity at all — would be the ones it dropped.
pub fn sql_identifier_is_resolvable(identifier: &str) -> String {
    format!("coalesce(btrim({identifier}, {SQL_PADDING}), '') <> ''")
}

/// The whole predicate as a SQL boolean, given a way to qualify a bare column name.
///
/// A fold over [`IDENTITY_COLUMNS`], so it is the same list `has_resolvable_identity` reads.
pub fn sql_has_resolvable_identity(qualify: impl Fn(&str) -> String) -> String {
    let clauses: Vec<String> = IDENTITY_COLUMNS
        .iter()
        .map(|c| sql_identifier_is_resolvable(&(c.sql_identifier)(&qualify(c.column), &qualify)))
        .collect();
    format!("({})", clauses.join(" OR "))
}

/// The negation of [`sql_has_resolvable_identity`]: rows with no identity to resolve.
pub fn sql_has_no_resolvable_identity(qualify: impl Fn(&str) -> String) -> String {
    format!("NOT {}", sql_has_resolvable_identity(qualify))
}

impl InterfaceBase {
    /// Whether this row names something the resolution ladder could look up.
    ///
    /// The single definition every layer defers to; see the module docs for what counts and why.
    pub fn has_resolvable_identity(&self) -> bool {
        IDENTITY_COLUMNS
            .iter()
            .any(|c| (c.identifier)(self).is_some_and(|id| identifier_is_resolvable(&id)))
    }

    /// The LLDP chassis id, if this arm has something to look up.
    ///
    /// The ladder's first arm, and the same reading [`has_resolvable_identity`] takes of the
    /// chassis column — [`chassis_identifier`] — so "this row has an identity" and "some arm
    /// applies to it" cannot come apart.
    ///
    /// That means a blank chassis id *does* take this arm when `lldp_sys_name` is usable, because
    /// the arm's own last rung is the `sysName` fallback and it places the row. What returning
    /// `None` stops is the case where the arm could do nothing at all: a blank chassis id with no
    /// system name behind it, which used to shadow a perfectly good `cdp_device_id`.
    ///
    /// [`has_resolvable_identity`]: InterfaceBase::has_resolvable_identity
    pub fn resolvable_chassis_id(&self) -> Option<&LldpChassisId> {
        let chassis_id = self.lldp_chassis_id.as_ref()?;
        chassis_identifier(self)
            .filter(|identifier| identifier_is_resolvable(identifier))
            .map(|_| chassis_id)
    }

    /// The CDP device id, if it names something worth looking up. The ladder's second arm.
    pub fn resolvable_cdp_device_id(&self) -> Option<&str> {
        self.cdp_device_id
            .as_deref()
            .filter(|id| identifier_is_resolvable(id))
    }

    /// A bridge-FDB port that learned exactly one address, so that address places the far end.
    ///
    /// Shared by the two questions that both turn on it — whether this row carries evidence of a
    /// neighbour at all, and whether an existing port binding could only have come from a MAC.
    pub fn has_single_fdb_mac(&self) -> bool {
        self.fdb_macs.as_ref().is_some_and(|macs| macs.len() == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::interfaces::r#impl::base::Neighbor;
    use crate::server::lldp::LldpPortId;
    use std::net::Ipv4Addr;
    use uuid::Uuid;

    /// A row shape, the verdict it must get, and why — the table every reading is run through.
    struct Shape {
        why: &'static str,
        base: InterfaceBase,
        resolvable: bool,
    }

    fn shape(
        why: &'static str,
        resolvable: bool,
        configure: impl FnOnce(&mut InterfaceBase),
    ) -> Shape {
        let mut base = InterfaceBase::default();
        configure(&mut base);
        Shape {
            why,
            base,
            resolvable,
        }
    }

    /// Every row shape the readings have to agree on, including each divergence the five
    /// hand-written copies of this rule used to have between them.
    fn shapes() -> Vec<Shape> {
        vec![
            shape("nothing at all", false, |_| {}),
            shape("an ordinary chassis MAC", true, |b| {
                b.lldp_chassis_id = Some(LldpChassisId::MacAddress("00:ad:24:af:4e:00".into()));
            }),
            shape("a chassis id that is a network address", true, |b| {
                b.lldp_chassis_id = Some(LldpChassisId::NetworkAddress(
                    Ipv4Addr::new(10, 0, 0, 1).into(),
                ));
            }),
            // The near-miss the issue records: admitted by `IS NOT NULL`, waved through by
            // `is_none()`, and then nothing to look up.
            shape("a chassis id present but empty", false, |b| {
                b.lldp_chassis_id = Some(LldpChassisId::LocallyAssigned(String::new()));
            }),
            shape("a chassis id that is only padding", false, |b| {
                b.lldp_chassis_id = Some(LldpChassisId::LocallyAssigned("  \t\r\n".into()));
            }),
            // The row the refactor silently dropped and review caught: `IS NOT NULL` selected it,
            // `is_none()` waved it through, it took the chassis arm, and `resolve_host_id` placed
            // it from the `sysName` fallback. Narrowing the predicate to the chassis id alone
            // stopped selecting it — no neighbour, no warning — so the fallback is part of what
            // the chassis arm's identifier *is*. See the module docs.
            shape("a blank chassis id but a usable system name", true, |b| {
                b.lldp_chassis_id = Some(LldpChassisId::LocallyAssigned(String::new()));
                b.lldp_sys_name = Some("core-sw1".into());
            }),
            shape("a blank chassis id and a blank system name", false, |b| {
                b.lldp_chassis_id = Some(LldpChassisId::MacAddress(String::new()));
                b.lldp_sys_name = Some("  \t".into());
            }),
            // Not new capability: a system name is the chassis arm's last rung, and with no
            // chassis id there is no arm for it to be the last rung of. Admitting one needs a
            // ladder arm first — see the module docs and `decode_tlv_name`.
            shape("a system name and nothing else", false, |b| {
                b.lldp_sys_name = Some("core-sw1".into());
            }),
            shape("a CDP device id", true, |b| {
                b.cdp_device_id = Some("core-sw1.example.com".into());
            }),
            shape("a CDP device id present but empty", false, |b| {
                b.cdp_device_id = Some("   ".into());
            }),
            // Divergence 1: in the SQL filter and the resolution guard, absent from the FDB
            // filter and the MAC-binding test. A management address is not the far end of a cable.
            shape("a CDP management address and nothing else", false, |b| {
                b.cdp_address = Some(Ipv4Addr::new(192, 0, 2, 7).into());
            }),
            // Divergence 2: admitted by `lldp_neighbors_in_network` alone. A resolution already
            // made is not an identity to resolve.
            shape(
                "an already-resolved neighbour and nothing else",
                false,
                |b| {
                    b.neighbor = Some(Neighbor::Host(Uuid::nil()));
                },
            ),
            // A port id names a port on a device this row cannot name.
            shape("a port id and nothing else", false, |b| {
                b.lldp_port_id = Some(LldpPortId::InterfaceName("Slot0/3".into()));
            }),
            shape("learned MAC addresses and nothing else", false, |b| {
                b.fdb_macs = Some(vec!["00:ad:24:af:4e:00".into()]);
            }),
            shape("a blank chassis id but a usable CDP device id", true, |b| {
                b.lldp_chassis_id = Some(LldpChassisId::LocallyAssigned(String::new()));
                b.cdp_device_id = Some("core-sw1".into());
            }),
            // GH #88 is a boundary guard, not this predicate: a chassis id full of control bytes
            // is still selected, still counted, and still warned about. See the module docs.
            shape("a chassis id holding control characters", true, |b| {
                b.lldp_chassis_id = Some(LldpChassisId::LocallyAssigned("sw\u{1}1".into()));
            }),
        ]
    }

    #[test]
    fn the_rust_predicate_answers_the_table() {
        for Shape {
            why,
            base,
            resolvable,
        } in shapes()
        {
            assert_eq!(
                base.has_resolvable_identity(),
                resolvable,
                "has_resolvable_identity disagrees about {why}"
            );
        }
    }

    /// The ladder picks its arm with `resolvable_chassis_id` / `resolvable_cdp_device_id`, so
    /// "some arm applies" and "this row has an identity" have to be the same statement. If they
    /// drift, a row is selected and then falls past every arm — no neighbour stored, no warning
    /// raised, which is the silent failure this whole change is about.
    #[test]
    fn an_arm_of_the_ladder_applies_to_exactly_the_rows_the_predicate_admits() {
        for Shape { why, base, .. } in shapes() {
            let an_arm_applies =
                base.resolvable_chassis_id().is_some() || base.resolvable_cdp_device_id().is_some();
            assert_eq!(
                an_arm_applies,
                base.has_resolvable_identity(),
                "the ladder and the predicate disagree about {why}"
            );
        }
    }

    /// A blank chassis id with nothing behind it must not shadow a usable CDP device id, which is
    /// the whole reason the arm condition is `resolvable_chassis_id()` and not
    /// `lldp_chassis_id.is_some()`.
    #[test]
    fn a_blank_chassis_id_does_not_take_the_ladders_first_arm() {
        let Shape { base, .. } = shape("", true, |b| {
            b.lldp_chassis_id = Some(LldpChassisId::LocallyAssigned(" ".into()));
            b.cdp_device_id = Some("core-sw1".into());
        });

        assert!(base.resolvable_chassis_id().is_none());
        assert_eq!(base.resolvable_cdp_device_id(), Some("core-sw1"));
    }

    /// ...but a blank chassis id with a usable `sysName` behind it *must* take it, because the
    /// `sysName` fallback is the last rung of that same arm and it places the row. This is the
    /// case narrowing the predicate to the chassis id alone silently dropped: not selected, not
    /// admitted, no neighbour stored and no warning raised.
    ///
    /// Asserted through the predicate and through the arm, because the two failures are
    /// different: the first stops the SQL selecting the row at all, the second lets it be
    /// selected and then fall past every arm.
    /// `crate::server::lldp` carries the third assertion — that the arm, once reached, resolves.
    #[test]
    fn a_blank_chassis_id_with_a_system_name_still_takes_the_ladders_first_arm() {
        let Shape { base, .. } = shape("", true, |b| {
            b.lldp_chassis_id = Some(LldpChassisId::LocallyAssigned(String::new()));
            b.lldp_sys_name = Some("core-sw1".into());
        });

        assert!(base.has_resolvable_identity());
        assert!(base.resolvable_chassis_id().is_some());

        // And the fallback is a rung of the *chassis* arm, not an identity of its own: take the
        // chassis id away and the same system name admits nothing.
        let Shape { base, .. } = shape("", false, |b| {
            b.lldp_sys_name = Some("core-sw1".into());
        });

        assert!(!base.has_resolvable_identity());
        assert!(base.resolvable_chassis_id().is_none());
    }

    /// What the SQL sees, modelled independently of the Rust accessors rather than reusing them:
    /// the row as it is stored (JSONB for the chassis id, text for the device id), read the way
    /// the generated expression reads it. Reusing `IdentityColumn::identifier` here would make the
    /// cross-check circular — it would only ever prove the emptiness rule, never the extraction.
    ///
    /// Unknown column panics on purpose: adding an entry to [`IDENTITY_COLUMNS`] without saying
    /// how Postgres would read it fails this test rather than silently going unchecked.
    fn sql_extracted(base: &InterfaceBase, column: &str) -> Option<String> {
        match column {
            // `coalesce(nullif(btrim(lldp_chassis_id ->> 'value', …), ''), case when
            // lldp_chassis_id ->> 'subtype' is not null then lldp_sys_name end)`, over the JSONB
            // the row actually stores. A JSON scalar `null` — what an absent chassis id
            // serialises to — has neither member, so both operators yield NULL, exactly as
            // Postgres would.
            "lldp_chassis_id" => {
                let stored =
                    serde_json::to_value(&base.lldp_chassis_id).expect("chassis id serialises");
                let member = |name: &str| {
                    stored
                        .get(name)
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                };
                match member("value").map(|v| btrim(&v)).filter(|v| !v.is_empty()) {
                    Some(identifier) => Some(identifier),
                    None => member("subtype").and(base.lldp_sys_name.clone()),
                }
            }
            "cdp_device_id" => base.cdp_device_id.clone(),
            other => panic!("no SQL model for identity column {other}"),
        }
    }

    /// Postgres' `btrim(…, SQL_PADDING)`: the padding characters stripped from both ends.
    fn btrim(value: &str) -> String {
        value
            .trim_matches(|c: char| c.is_ascii_whitespace())
            .to_string()
    }

    /// A row carrying *only* this entry's identity, for
    /// [`every_column_in_the_list_reaches_an_arm_of_the_ladder`].
    ///
    /// Unknown column panics on purpose, for the same reason [`sql_extracted`] does: adding an
    /// entry to [`IDENTITY_COLUMNS`] without saying what a row carrying it looks like fails this
    /// test rather than going unchecked.
    fn carrying_only(column: &str) -> InterfaceBase {
        let mut base = InterfaceBase::default();
        match column {
            "lldp_chassis_id" => {
                base.lldp_chassis_id = Some(LldpChassisId::MacAddress("00:ad:24:af:4e:00".into()));
            }
            "cdp_device_id" => base.cdp_device_id = Some("core-sw1.example.com".into()),
            other => panic!("no example row for identity column {other}"),
        }
        base
    }

    /// Postgres' reading of the fragment [`sql_identifier_is_resolvable`] emits: `btrim` strips
    /// the named characters from both ends, `coalesce` turns a NULL into the empty string, and the
    /// result is compared against `''`.
    ///
    /// A model, not the database — so it is deliberately small, and
    /// [`the_emitted_sql_is_the_fragment_this_model_reads`] pins it to the text actually
    /// generated, so it cannot go on modelling a fragment we stopped emitting.
    fn postgres_verdict(identifier: Option<&str>) -> bool {
        let btrimmed = identifier
            .unwrap_or("")
            .trim_matches(|c: char| c.is_ascii_whitespace());
        !btrimmed.is_empty()
    }

    /// The emitted SQL, spelled out, so the model above cannot quietly diverge from what runs.
    /// Changing the fragment has to be done here too, deliberately, with the model updated to
    /// match.
    #[test]
    fn the_emitted_sql_is_the_fragment_this_model_reads() {
        assert_eq!(
            sql_identifier_is_resolvable("x"),
            r"coalesce(btrim(x, E' \t\n\r\x0C'), '') <> ''"
        );
        assert_eq!(
            sql_has_resolvable_identity(|c| format!("interfaces.{c}")),
            concat!(
                r"(coalesce(btrim(coalesce(nullif(btrim(interfaces.lldp_chassis_id ->> 'value',",
                r" E' \t\n\r\x0C'), ''), case when interfaces.lldp_chassis_id ->> 'subtype' is not",
                r" null then interfaces.lldp_sys_name end), E' \t\n\r\x0C'), '') <> ''",
                r" OR coalesce(btrim(interfaces.cdp_device_id, E' \t\n\r\x0C'), '') <> '')",
            )
        );
        assert_eq!(
            sql_has_no_resolvable_identity(|c| format!("interfaces.{c}")),
            format!(
                "NOT {}",
                sql_has_resolvable_identity(|c| format!("interfaces.{c}"))
            )
        );
    }

    /// The padding the SQL trims, decoded from the escape string, must be exactly the set
    /// [`identifier_is_resolvable`] treats as padding. Emptiness is the one rule written twice in
    /// two languages, so this is the one place it can drift — and it nearly did: `btrim`'s
    /// obvious spelling of "ASCII whitespace" includes the vertical tab, which
    /// `char::is_ascii_whitespace` deliberately does not.
    #[test]
    fn the_sql_padding_set_is_exactly_ascii_whitespace() {
        let body = SQL_PADDING
            .strip_prefix("E'")
            .and_then(|s| s.strip_suffix('\''))
            .expect("SQL_PADDING is a Postgres escape string");

        let mut trimmed_by_sql = Vec::new();
        let mut chars = body.chars();
        while let Some(c) = chars.next() {
            trimmed_by_sql.push(match c {
                '\\' => match chars.next().expect("an escape has a body") {
                    't' => '\t',
                    'n' => '\n',
                    'r' => '\r',
                    'x' => {
                        let hex: String = (&mut chars).take(2).collect();
                        let code = u32::from_str_radix(&hex, 16).expect("two hex digits");
                        char::from_u32(code).expect("a character")
                    }
                    other => panic!("unmodelled Postgres escape \\{other}"),
                },
                c => c,
            });
        }
        trimmed_by_sql.sort_unstable();

        let treated_as_padding_by_rust: Vec<char> = (0u8..=127)
            .map(char::from)
            .filter(char::is_ascii_whitespace)
            .collect();

        assert_eq!(trimmed_by_sql, treated_as_padding_by_rust);
    }

    /// The same table of row shapes through the SQL semantics as through the Rust predicate. The
    /// shared list stops the two readings drifting apart in *membership*; this is what stops them
    /// drifting apart in *meaning*.
    #[test]
    fn the_sql_semantics_answer_the_table_identically() {
        for Shape {
            why,
            base,
            resolvable,
        } in shapes()
        {
            let by_sql = IDENTITY_COLUMNS
                .iter()
                .any(|c| postgres_verdict(sql_extracted(&base, c.column).as_deref()));
            assert_eq!(by_sql, resolvable, "the SQL reading disagrees about {why}");
            assert_eq!(
                by_sql,
                base.has_resolvable_identity(),
                "the two readings disagree about {why}"
            );
        }
    }

    /// Both readings are folds over the same list, so a column added to it reaches the SQL too.
    /// Asserted rather than left to review, because that is the failure mode this module exists to
    /// make impossible.
    #[test]
    fn every_column_in_the_list_reaches_the_sql() {
        let sql = sql_has_resolvable_identity(|c| format!("interfaces.{c}"));
        for column in IDENTITY_COLUMNS {
            assert!(
                sql.contains(&format!("interfaces.{}", column.column)),
                "{} is in the identity list but not in the SQL it generates",
                column.column
            );
        }
        assert_eq!(
            sql.matches(" <> ''").count(),
            IDENTITY_COLUMNS.len(),
            "the SQL has a clause count the identity list does not explain"
        );
    }

    /// The list has a *third* reading nothing else checks: the arms of the resolution ladder.
    ///
    /// `has_resolvable_identity` and the SQL are folds over the list and so cannot disagree with
    /// each other, but the ladder's arms are written out by hand in `resolve_lldp_links` and
    /// `build_neighbor_adjacency`. Review demonstrated the gap by adding a fully-wired
    /// `lldp_sys_name` entry with no arm behind it: every other test in this module still passed,
    /// and the effect on a real row would have been to select it and then drop it unjudged —
    /// which is the failure this module exists to make impossible.
    ///
    /// So: a row carrying only this entry's identity must be admitted *and* must reach an arm.
    /// Half-adopting a column now fails here.
    #[test]
    fn every_column_in_the_list_reaches_an_arm_of_the_ladder() {
        for IdentityColumn { column, .. } in IDENTITY_COLUMNS {
            let base = carrying_only(column);
            assert!(
                base.has_resolvable_identity(),
                "a row carrying only {column} is not admitted by the predicate that lists it"
            );
            assert!(
                base.resolvable_chassis_id().is_some() || base.resolvable_cdp_device_id().is_some(),
                "{column} is an identity the ladder has no arm for; such a row is selected and \
                 then falls past every arm, storing no neighbour and raising no warning"
            );
        }
    }

    /// The shape table run through a real PostgreSQL, so the cross-check above rests on a
    /// measurement rather than only on [`postgres_verdict`]'s reading of the manual.
    ///
    /// It is the same generated expression the filters emit, evaluated over the same rows as
    /// literals of the columns' real types. What the model could not have told us on its own:
    /// `jsonb 'null' ->> 'value'` yields NULL rather than erroring, a lone vertical tab is
    /// content and NBSP is content (`btrim` strips neither), a chassis object with no `value`
    /// member and one whose `value` is JSON `null` both read as no identifier, and `NOT (…)` over
    /// an all-NULL row is `true` rather than NULL — which is what
    /// `unresolved_fdb_in_network` depends on.
    ///
    /// `#[ignore]`-gated because it spins up a testcontainer, like the storage tests; opt in with:
    ///   `cargo test --lib the_generated_sql_answers_the_table_on_a_real_postgres -- --ignored`
    #[tokio::test]
    #[ignore = "spins up a PostgreSQL testcontainer; run with --ignored"]
    async fn the_generated_sql_answers_the_table_on_a_real_postgres() {
        let (pool, _database_url, _container) = crate::tests::setup_test_db().await;

        // Bare column names: the row under test is supplied as a one-row VALUES list, so the
        // predicate is exercised as text without needing the `interfaces` table or a migration.
        let predicate = sql_has_resolvable_identity(|c| c.to_string());
        let negation = sql_has_no_resolvable_identity(|c| c.to_string());

        for Shape {
            why,
            base,
            resolvable,
        } in shapes()
        {
            let query = format!(
                "SELECT {predicate} AS resolvable, {negation} AS unresolvable \
                 FROM (SELECT $1::jsonb AS lldp_chassis_id, $2::text AS cdp_device_id, \
                 $3::text AS lldp_sys_name) AS candidate"
            );
            let (by_postgres, negated): (bool, bool) = sqlx::query_as(&query)
                .bind(serde_json::to_value(&base.lldp_chassis_id).expect("chassis id serialises"))
                .bind(base.cdp_device_id.clone())
                .bind(base.lldp_sys_name.clone())
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("evaluating the predicate for {why}: {e}"));

            assert_eq!(by_postgres, resolvable, "PostgreSQL disagrees about {why}");
            assert_eq!(
                by_postgres,
                base.has_resolvable_identity(),
                "PostgreSQL and the Rust predicate disagree about {why}"
            );
            // Three-valued logic is the trap here: without the `coalesce`, a row with nothing in
            // it makes the negation NULL rather than true, and `unresolved_fdb_in_network` drops
            // exactly the rows it exists to find.
            assert_eq!(negated, !resolvable, "the negation is not total for {why}");
        }
    }
}
