import { createHmac, timingSafeEqual } from 'crypto';
import {
	NodeConnectionTypes,
	type IDataObject,
	type IHookFunctions,
	type ILoadOptionsFunctions,
	type INodePropertyOptions,
	type INodeType,
	type INodeTypeDescription,
	type IWebhookFunctions,
	type IWebhookResponseData,
} from 'n8n-workflow';

const EVENTS = {
	finished: ['verification.completed', 'verification.reviewed'],
	review: ['verification.review_required'],
	expired: ['verification.expired'],
} as const;

/** Checks the secuveri-signature header (t=…,v1=…) with five minutes' tolerance. */
export function verifySignature(rawBody: string, header: string | undefined, secret: string | undefined, now = Date.now()): boolean {
	if (!secret || !header) return false;
	let timestamp: number | null = null;
	const signatures: string[] = [];
	for (const part of header.split(',')) {
		const index = part.indexOf('=');
		if (index <= 0) continue;
		const key = part.slice(0, index).trim();
		const value = part.slice(index + 1).trim();
		if (key === 't' && /^\d{1,12}$/.test(value)) timestamp = Number(value);
		if (key === 'v1' && value) signatures.push(value.toLowerCase());
	}
	if (timestamp === null || !signatures.length || Math.abs(Math.floor(now / 1000) - timestamp) > 300) return false;
	const expected = createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
	return signatures.some(
		(signature) => signature.length === expected.length && timingSafeEqual(Buffer.from(signature), Buffer.from(expected)),
	);
}

export class SecuveriTrigger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'secuveri Trigger',
		name: 'secuveriTrigger',
		icon: { light: 'file:../../icons/secuveri.svg', dark: 'file:../../icons/secuveri.dark.svg' },
		group: ['trigger'],
		version: 1,
		subtitle: '={{$parameter["event"]}}',
		description: 'Starts the workflow when a secuveri verification finishes, needs review or expires',
		defaults: { name: 'secuveri Trigger' },
		inputs: [],
		outputs: [NodeConnectionTypes.Main],
		credentials: [{ name: 'secuveriApi', required: true }],
		webhooks: [{ name: 'default', httpMethod: 'POST', responseMode: 'onReceived', path: 'webhook' }],
		properties: [
			{
				displayName: 'Event',
				name: 'event',
				type: 'options',
				options: [
					{ name: 'Verification Finished', value: 'finished', description: 'Automatically or by a reviewer' },
					{ name: 'Verification Needs Review', value: 'review' },
					{ name: 'Verification Expired', value: 'expired', description: 'The person did not finish in time' },
				],
				default: 'finished',
			},
			{
				displayName: 'Outcome',
				name: 'outcome',
				type: 'options',
				options: [
					{ name: 'Any', value: 'any' },
					{ name: 'Approved', value: 'approved' },
					{ name: 'Declined or Failed', value: 'declined' },
				],
				default: 'any',
				displayOptions: { show: { event: ['finished'] } },
			},
			{
				displayName: 'Workflow Name or ID',
				name: 'workflowId',
				type: 'options',
				typeOptions: { loadOptionsMethod: 'getWorkflows' },
				default: '',
				description:
					'Only verifications of this secuveri workflow. Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code/expressions/">expression</a>.',
			},
		],
	};

	methods = {
		loadOptions: {
			async getWorkflows(this: ILoadOptionsFunctions): Promise<INodePropertyOptions[]> {
				const credentials = await this.getCredentials('secuveriApi');
				const response = (await this.helpers.httpRequestWithAuthentication.call(this, 'secuveriApi', {
					method: 'GET',
					url: `${credentials.baseUrl}/v1/workflows`,
					json: true,
				})) as { workflows: { id: string; name: string }[] };
				return [
					{ name: 'Any Workflow', value: '' },
					...response.workflows.map((w) => ({ name: w.name, value: w.id })),
				];
			},
		},
	};

	webhookMethods = {
		default: {
			async checkExists(this: IHookFunctions): Promise<boolean> {
				const data = this.getWorkflowStaticData('node');
				if (!data.webhookId) return false;
				const credentials = await this.getCredentials('secuveriApi');
				const response = (await this.helpers.httpRequestWithAuthentication.call(this, 'secuveriApi', {
					method: 'GET',
					url: `${credentials.baseUrl}/v1/webhooks`,
					json: true,
				})) as { webhooks: { id: string; url: string }[] };
				const url = this.getNodeWebhookUrl('default');
				const found = response.webhooks.some((hook) => hook.id === data.webhookId && hook.url === url);
				if (!found) delete data.webhookId;
				return found;
			},

			async create(this: IHookFunctions): Promise<boolean> {
				const credentials = await this.getCredentials('secuveriApi');
				const event = this.getNodeParameter('event') as keyof typeof EVENTS;
				const response = (await this.helpers.httpRequestWithAuthentication.call(this, 'secuveriApi', {
					method: 'POST',
					url: `${credentials.baseUrl}/v1/webhooks`,
					body: { url: this.getNodeWebhookUrl('default'), events: EVENTS[event], description: 'n8n' },
					json: true,
				})) as { webhook: { id: string }; secret: string };
				const data = this.getWorkflowStaticData('node');
				data.webhookId = response.webhook.id;
				// Shown once; kept with the workflow to check each delivery.
				data.webhookSecret = response.secret;
				return true;
			},

			async delete(this: IHookFunctions): Promise<boolean> {
				const data = this.getWorkflowStaticData('node');
				if (!data.webhookId) return true;
				const credentials = await this.getCredentials('secuveriApi');
				try {
					await this.helpers.httpRequestWithAuthentication.call(this, 'secuveriApi', {
						method: 'DELETE',
						url: `${credentials.baseUrl}/v1/webhooks/${data.webhookId as string}`,
						json: true,
					});
				} catch (error) {
					// Already removed in the dashboard.
					if ((error as { httpCode?: string }).httpCode !== '404') return false;
				}
				delete data.webhookId;
				delete data.webhookSecret;
				return true;
			},
		},
	};

	async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
		const request = this.getRequestObject() as { rawBody?: Buffer; body: IDataObject };
		const header = this.getHeaderData()['secuveri-signature'] as string | undefined;
		const secret = this.getWorkflowStaticData('node').webhookSecret as string | undefined;
		const raw = request.rawBody ? request.rawBody.toString('utf8') : JSON.stringify(request.body);
		if (!verifySignature(raw, header, secret)) return { webhookResponse: 'ignored', workflowData: [] };

		const event = request.body as { id?: string; type?: string; created_at?: string; data?: IDataObject };
		const record: IDataObject = { id: event.id, event_type: event.type, created_at: event.created_at, ...(event.data ?? {}) };

		const workflowId = this.getNodeParameter('workflowId', '') as string;
		if (workflowId && record.workflow_id !== workflowId) return { workflowData: [] };
		if (this.getNodeParameter('event') === 'finished') {
			if (record.status === 'REVIEW_REQUIRED') return { workflowData: [] };
			const outcome = this.getNodeParameter('outcome', 'any') as string;
			if (outcome === 'approved' && record.verdict !== 'APPROVED') return { workflowData: [] };
			if (outcome === 'declined' && record.verdict === 'APPROVED') return { workflowData: [] };
		}
		return { workflowData: [this.helpers.returnJsonArray([record])] };
	}
}
