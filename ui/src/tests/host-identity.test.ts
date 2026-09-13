import { describe, expect, it } from 'vitest';
import { describeIdentity } from '$lib/features/hosts/host-identity';
import type { HostNameLadderEntry } from '$lib/features/hosts/types/base';

/**
 * What the host editor says about a host's name.
 *
 * The ladders below stand in for the server's `name_ladder`: every rung in the server's order,
 * blanks already dropped. The cases are the hosts the editor has to explain: one a person named,
 * one discovery named, one titled by its sysName, one titled by its address, and one with nothing.
 */

const SNMP = { Probe: 'Snmp' } as const;

function ladder(
	values: Partial<Record<HostNameLadderEntry['rung'], [string, HostNameLadderEntry['source']]>>
): HostNameLadderEntry[] {
	return (['Name', 'Hostname', 'SysName', 'ChassisId', 'Address'] as const).map((rung) => ({
		rung,
		value: values[rung]?.[0] ?? null,
		source: values[rung]?.[1] ?? null
	}));
}

describe('describeIdentity', () => {
	it('says a person named a host whose saved name was typed in Scanopy, and offers a way back', () => {
		const view = describeIdentity({
			ladder: ladder({ Name: ['Core Switch', 'Manual'], SysName: ['core-sw-01', SNMP] }),
			savedName: 'Core Switch',
			nameSource: 'Manual',
			liveName: 'Core Switch'
		});

		expect(view.statement).toEqual({ kind: 'namedByPerson' });
		expect(view.canRevert).toBe(true);
		expect(view.winningRung).toBe('Name');
	});

	it('credits discovery with a name it supplied, and offers no revert to the same name', () => {
		const view = describeIdentity({
			ladder: ladder({ Name: ['core-sw-01', SNMP], SysName: ['core-sw-01', SNMP] }),
			savedName: 'core-sw-01',
			nameSource: SNMP,
			liveName: 'core-sw-01'
		});

		expect(view.statement).toEqual({ kind: 'namedByDiscovery', source: SNMP });
		expect(view.canRevert).toBe(false);
	});

	it('keeps an unattributed name distinct from one a person typed', () => {
		const view = describeIdentity({
			ladder: ladder({ Name: ['nas.lan', 'Unspecified'] }),
			savedName: 'nas.lan',
			nameSource: 'Unspecified',
			liveName: 'nas.lan'
		});

		expect(view.statement).toEqual({ kind: 'namedByDiscovery', source: 'Unspecified' });
	});

	it('titles a nameless host by its sysName when that is the highest rung it holds', () => {
		const view = describeIdentity({
			ladder: ladder({ SysName: ['printer-hp-main', SNMP], Address: ['10.0.30.50', null] }),
			savedName: '',
			nameSource: 'Unspecified',
			liveName: ''
		});

		expect(view.statement).toEqual({
			kind: 'shownAs',
			value: 'printer-hp-main',
			rung: 'SysName',
			source: SNMP
		});
		expect(view.winningRung).toBe('SysName');
	});

	it('titles a host with nothing else by its address, with no source to claim', () => {
		const view = describeIdentity({
			ladder: ladder({ Address: ['10.0.30.61', null] }),
			savedName: '',
			nameSource: 'Unspecified',
			liveName: ''
		});

		expect(view.statement).toEqual({
			kind: 'shownAs',
			value: '10.0.30.61',
			rung: 'Address',
			source: null
		});
	});

	it('previews the discovered name as soon as the Name field is cleared, before saving', () => {
		const view = describeIdentity({
			ladder: ladder({ Name: ['Core Switch', 'Manual'], Hostname: ['switch.lan', null] }),
			savedName: 'Core Switch',
			nameSource: 'Manual',
			liveName: '   '
		});

		expect(view.statement).toMatchObject({ kind: 'shownAs', value: 'switch.lan' });
		expect(view.winningRung).toBe('Hostname');
		expect(view.canRevert).toBe(false);
	});

	it('treats an unsaved new name as a rename, whatever named the host before', () => {
		const view = describeIdentity({
			ladder: ladder({ Name: ['core-sw-01', SNMP] }),
			savedName: 'core-sw-01',
			nameSource: SNMP,
			liveName: 'Rack 3 Top Switch'
		});

		expect(view.statement).toEqual({ kind: 'renaming' });
		expect(view.canRevert).toBe(true);
	});

	it('says nothing identifies a host with no name and no evidence', () => {
		const view = describeIdentity({
			ladder: ladder({}),
			savedName: '',
			nameSource: 'Unspecified',
			liveName: ''
		});

		expect(view.statement).toEqual({ kind: 'unnamed' });
		expect(view.winningRung).toBeNull();
	});
});
