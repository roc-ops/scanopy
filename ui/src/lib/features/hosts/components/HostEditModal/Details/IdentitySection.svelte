<script lang="ts">
	import type { AnyFieldApi } from '@tanstack/svelte-form';
	import { CircleCheck } from 'lucide-svelte';
	import type { HostFormData } from '$lib/features/hosts/types/base';
	import { describeIdentity, rungLabel } from '$lib/features/hosts/host-identity';
	import { hostnameFormat, max } from '$lib/shared/components/forms/validators';
	import TextInput from '$lib/shared/components/forms/input/TextInput.svelte';
	import AttributeSourceTag from '$lib/shared/components/data/AttributeSourceTag.svelte';
	import {
		common_hostname,
		common_name,
		common_none,
		common_placeholderHostname,
		hosts_details_namePlaceholder,
		hosts_identity_heading,
		hosts_identity_inUse,
		hosts_identity_ladderHelp,
		hosts_identity_namedByDiscovery,
		hosts_identity_namedByPerson,
		hosts_identity_renaming,
		hosts_identity_shownAs,
		hosts_identity_unnamed,
		hosts_identity_useDiscoveredName,
		hosts_unnamedHost
	} from '$lib/paraglide/messages';

	interface Props {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		form: { Field: any; setFieldValue: (field: 'name', value: string) => void };
		formData: HostFormData;
		isEditing: boolean;
	}

	let { form, formData, isEditing }: Props = $props();

	// The Name field's live value. TanStack's field state is not tracked by `$derived`, so the
	// statement reads this instead. A writable derived: it resets to the saved name whenever the
	// editor loads a host into `formData`, and the input and the revert button overwrite it between.
	let liveName = $derived(formData.name ?? '');

	let view = $derived(
		describeIdentity({
			ladder: formData.name_ladder ?? [],
			savedName: formData.name ?? '',
			nameSource: formData.name_source,
			liveName
		})
	);

	// The rungs below Name, in the server's order. Name itself is the field above them.
	let evidence = $derived((formData.name_ladder ?? []).filter((entry) => entry.rung !== 'Name'));

	function useDiscoveredName() {
		liveName = '';
		form.setFieldValue('name', '');
	}
</script>

{#snippet hostnameField(label: string)}
	<form.Field
		name="hostname"
		validators={{
			onBlur: ({ value }: { value: string }) => hostnameFormat(value)
		}}
	>
		{#snippet children(field: AnyFieldApi)}
			<TextInput {label} id="hostname" placeholder={common_placeholderHostname()} {field} />
		{/snippet}
	</form.Field>
{/snippet}

<section class="space-y-4">
	<h3 class="text-primary text-sm font-semibold">{hosts_identity_heading()}</h3>

	<div class="grid gap-6" class:grid-cols-2={!isEditing}>
		<div
			oninput={(event) => {
				if (event.target instanceof HTMLInputElement) liveName = event.target.value;
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
						label={common_name()}
						id="name"
						placeholder={hosts_details_namePlaceholder()}
						{field}
					/>
				{/snippet}
			</form.Field>
		</div>

		{#if !isEditing}
			{@render hostnameField(common_hostname())}
		{/if}
	</div>

	{#if isEditing}
		<div class="flex flex-wrap items-center gap-x-3 gap-y-2 text-sm">
			{#if view.statement.kind === 'namedByPerson'}
				<span class="text-secondary">{hosts_identity_namedByPerson()}</span>
			{:else if view.statement.kind === 'renaming'}
				<span class="text-secondary">{hosts_identity_renaming()}</span>
			{:else if view.statement.kind === 'namedByDiscovery'}
				<span class="text-secondary">{hosts_identity_namedByDiscovery()}</span>
				<AttributeSourceTag source={view.statement.source} />
			{:else if view.statement.kind === 'shownAs'}
				<span class="text-secondary">
					{hosts_identity_shownAs({
						name: view.statement.value,
						rung: rungLabel(view.statement.rung)
					})}
				</span>
				<AttributeSourceTag source={view.statement.source} />
			{:else}
				<span class="text-secondary">{hosts_identity_unnamed({ name: hosts_unnamedHost() })}</span>
			{/if}
			{#if view.canRevert}
				<button type="button" class="text-blue-400 hover:text-blue-300" onclick={useDiscoveredName}>
					{hosts_identity_useDiscoveredName()}
				</button>
			{/if}
		</div>

		{#if evidence.length > 0}
			<div class="card card-static space-y-3">
				<p class="text-secondary text-xs">{hosts_identity_ladderHelp()}</p>
				<ol class="space-y-3">
					{#each evidence as entry (entry.rung)}
						{@const winning = view.winningRung === entry.rung}
						<li class="flex flex-wrap items-center gap-x-4 gap-y-2">
							{#if entry.rung === 'Hostname'}
								<div class="min-w-0 flex-1">{@render hostnameField(rungLabel(entry.rung))}</div>
							{:else}
								<div class="flex min-w-0 flex-1 items-baseline gap-3">
									<span class="text-secondary w-32 shrink-0 text-sm">{rungLabel(entry.rung)}</span>
									{#if entry.value}
										<span
											class="text-primary min-w-0 break-all text-sm"
											class:font-mono={entry.rung !== 'SysName'}>{entry.value}</span
										>
									{:else}
										<span class="text-secondary text-sm italic">{common_none()}</span>
									{/if}
								</div>
							{/if}
							<div class="flex shrink-0 items-center gap-3">
								{#if entry.value || entry.rung === 'Hostname'}
									<AttributeSourceTag source={entry.source} />
								{/if}
								{#if winning}
									<span class="flex items-center gap-1 text-xs font-medium text-green-400">
										<CircleCheck class="h-3.5 w-3.5" />
										{hosts_identity_inUse()}
									</span>
								{/if}
							</div>
						</li>
					{/each}
				</ol>
			</div>
		{/if}
	{/if}
</section>
