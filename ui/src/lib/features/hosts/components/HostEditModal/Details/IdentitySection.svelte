<script lang="ts">
	import type { AnyFieldApi } from '@tanstack/svelte-form';
	import { untrack } from 'svelte';
	import type { HostFormData } from '$lib/features/hosts/types/base';
	import { discoveredName, overrideOf, rungLabel } from '$lib/features/hosts/host-identity';
	import { hostnameFormat, max } from '$lib/shared/components/forms/validators';
	import TextInput from '$lib/shared/components/forms/input/TextInput.svelte';
	import AttributeSourceTag from '$lib/shared/components/data/AttributeSourceTag.svelte';
	import {
		common_hostname,
		common_name,
		common_placeholderHostname,
		hosts_details_namePlaceholder,
		hosts_identity_discoveredName,
		hosts_identity_fromRung,
		hosts_identity_nothingDiscovered,
		hosts_identity_overrideHelp,
		hosts_identity_overrideLabel,
		hosts_identity_overridden,
		hosts_unnamedHost
	} from '$lib/paraglide/messages';

	interface Props {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		form: { Field: any };
		formData: HostFormData;
		isEditing: boolean;
	}

	let { form, formData, isEditing }: Props = $props();

	// Server data, so it stays what was discovered whatever the override field holds.
	let discovered = $derived(discoveredName(formData.name_ladder ?? []));

	// The override field's live value, for the "overridden" note. TanStack's field state is not
	// tracked by `$derived`, so this follows the input instead. It resets when the editor loads a
	// different host, keyed on the id: submit-time sync writes `formData.name` and must not reset it.
	let liveOverride = $derived.by(() => {
		void formData.id;
		return untrack(() => overrideOf(formData.name ?? '', formData.name_source));
	});
</script>

<div class="card card-static space-y-5">
	{#if isEditing}
		<div class="space-y-1">
			<div class="text-secondary text-xs font-medium uppercase tracking-wide">
				{hosts_identity_discoveredName()}
			</div>
			{#if discovered}
				<div class="text-primary break-all text-lg font-semibold">{discovered.value}</div>
				<div class="flex flex-wrap items-center gap-2 text-sm">
					{#if discovered.rung !== 'Name'}
						<span class="text-secondary">
							{hosts_identity_fromRung({ rung: rungLabel(discovered.rung) })}
						</span>
					{/if}
					{#if discovered.source}
						<AttributeSourceTag source={discovered.source} />
					{/if}
					{#if liveOverride.trim()}
						<span class="text-secondary italic">{hosts_identity_overridden()}</span>
					{/if}
				</div>
			{:else}
				<div class="text-secondary text-lg font-semibold">{hosts_unnamedHost()}</div>
				<div class="text-secondary text-sm">{hosts_identity_nothingDiscovered()}</div>
			{/if}
		</div>

		<div
			oninput={(event) => {
				if (event.target instanceof HTMLInputElement) liveOverride = event.target.value;
			}}
		>
			<form.Field
				name="name"
				validators={{
					onBlur: ({ value }: { value: string }) => max(100)(value)
				}}
			>
				{#snippet children(field: AnyFieldApi)}
					<TextInput
						label={hosts_identity_overrideLabel()}
						id="name"
						placeholder={discovered?.value ?? hosts_unnamedHost()}
						helpText={hosts_identity_overrideHelp()}
						{field}
					/>
				{/snippet}
			</form.Field>
		</div>
	{:else}
		<div class="grid grid-cols-2 gap-6">
			<form.Field
				name="name"
				validators={{
					onBlur: ({ value }: { value: string }) => max(100)(value)
				}}
			>
				{#snippet children(field: AnyFieldApi)}
					<TextInput
						label={common_name()}
						id="name"
						placeholder={hosts_details_namePlaceholder()}
						{field}
					/>
				{/snippet}
			</form.Field>

			<form.Field
				name="hostname"
				validators={{
					onBlur: ({ value }: { value: string }) => hostnameFormat(value)
				}}
			>
				{#snippet children(field: AnyFieldApi)}
					<TextInput
						label={common_hostname()}
						id="hostname"
						placeholder={common_placeholderHostname()}
						{field}
					/>
				{/snippet}
			</form.Field>
		</div>
	{/if}
</div>
