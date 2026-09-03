<script lang="ts">
	import { useQueryClient } from '@tanstack/svelte-query';
	import { queryKeys } from '$lib/api/query-client';
	import type { Interface, IPAddress } from '$lib/features/hosts/types/base';
	import { getHostByIdFromCache } from '$lib/features/hosts/queries';
	import { getSubnetByIdFromCache } from '$lib/features/subnets/queries';
	import ConfigHeader from '$lib/shared/components/forms/config/ConfigHeader.svelte';
	import CollapsibleCard from '$lib/shared/components/data/CollapsibleCard.svelte';
	import InfoRow from '$lib/shared/components/data/InfoRow.svelte';
	import InterfaceDetailsCard from '$lib/features/hosts/components/InterfaceDetailsCard.svelte';
	import {
		hosts_interfaces_cdpNeighbor,
		hosts_interfaces_index,
		hosts_interfaces_lldpNeighbor,
		hosts_interfaces_managementAddress,
		hosts_interfaces_portId,
		hosts_interfaces_remoteAddress,
		hosts_interfaces_remoteDevice,
		hosts_interfaces_remotePlatform,
		hosts_interfaces_remotePort,
		hosts_interfaces_remoteSystemName,
		hosts_snmp_chassisId,
		hosts_snmp_sysDescr,
		hosts_unnamedInterface
	} from '$lib/paraglide/messages';

	interface Props {
		iface: Interface;
	}

	let { iface }: Props = $props();

	const queryClient = useQueryClient();

	// Linked IPAddress + Subnet resolution
	let linkedIpAddress = $derived.by(() => {
		if (!iface.ip_address_id) return null;
		const allIpAddresses = queryClient.getQueryData<IPAddress[]>(queryKeys.ipAddresses.all) ?? [];
		return allIpAddresses.find((i) => i.id === iface.ip_address_id) ?? null;
	});

	let linkedSubnet = $derived.by(() => {
		if (!linkedIpAddress) return null;
		return getSubnetByIdFromCache(queryClient, linkedIpAddress.subnet_id);
	});

	// Neighbor resolution
	let neighborHost = $derived.by(() => {
		if (!iface.neighbor) return null;
		if (iface.neighbor.type === 'Host') {
			return getHostByIdFromCache(queryClient, iface.neighbor.id);
		}
		const allInterfaces = queryClient.getQueryData<Interface[]>(queryKeys.interfaces.all) ?? [];
		const remoteEntry = allInterfaces.find((e) => e.id === iface.neighbor!.id);
		if (remoteEntry) {
			return getHostByIdFromCache(queryClient, remoteEntry.host_id);
		}
		return null;
	});

	let neighborInterface = $derived.by(() => {
		if (!iface.neighbor || iface.neighbor.type !== 'Interface') return null;
		const allInterfaces = queryClient.getQueryData<Interface[]>(queryKeys.interfaces.all) ?? [];
		return allInterfaces.find((e) => e.id === iface.neighbor!.id) ?? null;
	});

	let cdpExpanded = $state(false);
	let lldpExpanded = $state(false);
</script>

<div class="space-y-6">
	<ConfigHeader
		title={iface.if_name || iface.if_descr || hosts_unnamedInterface()}
		subtitle={iface.if_index == null ? null : hosts_interfaces_index({ index: iface.if_index })}
	/>

	<InterfaceDetailsCard
		{iface}
		{linkedIpAddress}
		{linkedSubnet}
		{neighborHost}
		{neighborInterface}
	/>

	<!-- CDP Neighbor Info Section -->
	<CollapsibleCard title={hosts_interfaces_cdpNeighbor()} bind:expanded={cdpExpanded}>
		<InfoRow label={hosts_interfaces_remoteDevice()}>{iface.cdp_device_id || '-'}</InfoRow>
		<InfoRow label={hosts_interfaces_remotePort()}>{iface.cdp_port_id || '-'}</InfoRow>
		<InfoRow label={hosts_interfaces_remoteAddress()} mono>{iface.cdp_address || '-'}</InfoRow>
		<InfoRow label={hosts_interfaces_remotePlatform()}>{iface.cdp_platform || '-'}</InfoRow>
	</CollapsibleCard>

	<!-- LLDP Neighbor Info Section -->
	<CollapsibleCard title={hosts_interfaces_lldpNeighbor()} bind:expanded={lldpExpanded}>
		<InfoRow label={hosts_snmp_chassisId()} mono>{iface.lldp_chassis_id?.value || '-'}</InfoRow>
		<InfoRow label={hosts_interfaces_portId()} mono>{iface.lldp_port_id?.value || '-'}</InfoRow>
		<InfoRow label={hosts_interfaces_remoteSystemName()}>{iface.lldp_sys_name || '-'}</InfoRow>
		<InfoRow label={hosts_interfaces_remotePort()}>{iface.lldp_port_desc || '-'}</InfoRow>
		<InfoRow label={hosts_interfaces_managementAddress()} mono
			>{iface.lldp_mgmt_addr || '-'}</InfoRow
		>
		<InfoRow label={hosts_snmp_sysDescr()}>{iface.lldp_sys_desc || '-'}</InfoRow>
	</CollapsibleCard>
</div>
