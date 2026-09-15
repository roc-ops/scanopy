import type { components } from '$lib/api/schema';
import {
	common_hostname,
	common_ipAddress,
	common_name,
	hosts_snmp_chassisId,
	hosts_snmp_sysName
} from '$lib/paraglide/messages';
import type { HostNameLadderEntry, HostNameRung } from './types/base';

type AttributeSource = components['schemas']['AttributeSource'];

/**
 * What the host editor says about a host's name, decided without rendering anything.
 *
 * The ladder itself is `Host::name_ladder` on the server, sent as `name_ladder`: the rungs, their
 * order, their values with blanks already dropped, and each value's source. This module never
 * walks rungs of its own (see `host-display-name.ts` for why a second copy is forbidden). It does
 * one thing the server cannot: react to the Name field before it is saved. With Name blank, the
 * host is titled by the first entry below `Name` that holds a value, which is the server's own
 * resolution rule applied to the server's own list.
 */
export type IdentityStatement =
	/** A person typed the saved name into Scanopy. */
	| { kind: 'namedByPerson' }
	/** Discovery supplied the saved name. `source` is who. */
	| { kind: 'namedByDiscovery'; source: AttributeSource | null }
	/** The Name field holds an unsaved new name. */
	| { kind: 'renaming' }
	/** Name is blank, so the host is titled by a lower rung. */
	| { kind: 'shownAs'; value: string; rung: HostNameRung; source: AttributeSource | null }
	/** Name is blank and no rung holds anything. */
	| { kind: 'unnamed' };

export interface IdentityView {
	statement: IdentityStatement;
	/** Whether to offer clearing Name, so the host goes back to its discovered name. */
	canRevert: boolean;
	/** The rung that titles the host as the form stands. `null` when nothing does. */
	winningRung: HostNameRung | null;
}

export interface IdentityInput {
	/** The saved host's ladder, highest rung first. Empty for a host not saved yet. */
	ladder: HostNameLadderEntry[];
	/** The name as saved. */
	savedName: string;
	/** Who supplied the saved name. */
	nameSource: AttributeSource | undefined;
	/** The Name field as it stands now. */
	liveName: string;
}

export function describeIdentity({
	ladder,
	savedName,
	nameSource,
	liveName
}: IdentityInput): IdentityView {
	if (liveName.trim()) {
		if (liveName !== savedName) {
			return { statement: { kind: 'renaming' }, canRevert: true, winningRung: 'Name' };
		}
		if (nameSource === 'Manual') {
			return { statement: { kind: 'namedByPerson' }, canRevert: true, winningRung: 'Name' };
		}
		return {
			statement: { kind: 'namedByDiscovery', source: nameSource ?? null },
			canRevert: false,
			winningRung: 'Name'
		};
	}

	const fallback = ladder.find((entry) => entry.rung !== 'Name' && entry.value);
	if (!fallback?.value) {
		return { statement: { kind: 'unnamed' }, canRevert: false, winningRung: null };
	}
	return {
		statement: {
			kind: 'shownAs',
			value: fallback.value,
			rung: fallback.rung,
			source: fallback.source ?? null
		},
		canRevert: false,
		winningRung: fallback.rung
	};
}

/** Labels reuse the field names each rung already has elsewhere in the editor. */
const RUNG_LABELS: Record<HostNameRung, () => string> = {
	Name: () => common_name(),
	Hostname: () => common_hostname(),
	SysName: () => hosts_snmp_sysName(),
	ChassisId: () => hosts_snmp_chassisId(),
	Address: () => common_ipAddress()
};

export function rungLabel(rung: HostNameRung): string {
	return RUNG_LABELS[rung]();
}
