<script lang="ts">
	import type { HostFormData } from '$lib/features/hosts/types/base';
	import type { AttributeSource } from '$lib/shared/utils/attribute-source';
	import AttributeSourceTag from '$lib/shared/components/data/AttributeSourceTag.svelte';
	import {
		common_contact,
		common_firmwareRevision,
		common_hardware,
		common_location,
		common_manufacturer,
		common_model,
		common_serialNumber,
		common_softwareRevision,
		hosts_deviceFacts_firmwareGroup,
		hosts_deviceFacts_heading,
		hosts_deviceFacts_locationGroup,
		hosts_snmp_managementUrl,
		hosts_snmp_sysDescr,
		hosts_snmp_sysObjectId
	} from '$lib/paraglide/messages';

	let { host }: { host: HostFormData } = $props();

	interface Fact {
		label: string;
		value: string | null | undefined;
		source: AttributeSource | undefined;
		mono?: boolean;
		link?: boolean;
	}

	// Grouped by what each value describes, not by the protocol that carried it. A model arrives
	// from ENTITY-MIB, a controller or an industrial probe, and each value's own tag says which.
	let groups = $derived(
		[
			{
				title: common_hardware(),
				facts: [
					{
						label: common_manufacturer(),
						value: host.manufacturer,
						source: host.manufacturer_source
					},
					{ label: common_model(), value: host.model, source: host.model_source, mono: true },
					{
						label: common_serialNumber(),
						value: host.serial_number,
						source: host.serial_number_source,
						mono: true
					},
					{
						label: hosts_snmp_sysObjectId(),
						value: host.sys_object_id,
						source: host.sys_object_id_source,
						mono: true
					}
				] satisfies Fact[]
			},
			{
				title: hosts_deviceFacts_firmwareGroup(),
				facts: [
					{
						label: common_firmwareRevision(),
						value: host.firmware_revision,
						source: host.firmware_revision_source,
						mono: true
					},
					{
						label: common_softwareRevision(),
						value: host.software_revision,
						source: host.software_revision_source,
						mono: true
					},
					{ label: hosts_snmp_sysDescr(), value: host.sys_descr, source: host.sys_descr_source }
				] satisfies Fact[]
			},
			{
				title: hosts_deviceFacts_locationGroup(),
				facts: [
					{ label: common_location(), value: host.sys_location, source: host.sys_location_source },
					{ label: common_contact(), value: host.sys_contact, source: host.sys_contact_source },
					{
						label: hosts_snmp_managementUrl(),
						value: host.management_url,
						source: host.management_url_source,
						link: true
					}
				] satisfies Fact[]
			}
		]
			.map((group) => ({
				...group,
				facts: (group.facts as Fact[]).filter((fact) => fact.value?.trim())
			}))
			.filter((group) => group.facts.length > 0)
	);
</script>

{#if groups.length > 0}
	<section class="space-y-4">
		<h3 class="text-primary text-sm font-semibold">{hosts_deviceFacts_heading()}</h3>
		<div class="grid gap-4 md:grid-cols-3">
			{#each groups as group (group.title)}
				<div class="card card-static space-y-4">
					<h4 class="text-secondary text-xs font-semibold uppercase tracking-wide">
						{group.title}
					</h4>
					{#each group.facts as fact (fact.label)}
						<div class="space-y-1">
							<div class="text-secondary text-xs">{fact.label}</div>
							<div class="text-primary break-words text-sm" class:font-mono={fact.mono}>
								{#if fact.link}
									<!-- eslint-disable svelte/no-navigation-without-resolve -->
									<a
										href={fact.value}
										target="_blank"
										rel="external noopener noreferrer"
										class="break-all text-blue-400 hover:text-blue-300"
									>
										{fact.value}
									</a>
									<!-- eslint-enable svelte/no-navigation-without-resolve -->
								{:else}
									{fact.value}
								{/if}
							</div>
							<AttributeSourceTag source={fact.source} />
						</div>
					{/each}
				</div>
			{/each}
		</div>
	</section>
{/if}
