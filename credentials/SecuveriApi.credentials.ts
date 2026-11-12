import type {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
	Icon,
} from 'n8n-workflow';

export class SecuveriApi implements ICredentialType {
	name = 'secuveriApi';

	// Title case is required by n8n's verification scan; elsewhere the brand stays lowercase.
	displayName = 'Secuveri API';

	icon: Icon = { light: 'file:../icons/secuveri.svg', dark: 'file:../icons/secuveri.dark.svg' };

	documentationUrl = 'https://app.secuveri.com/docs';

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description:
				'An organization API key from Settings > API keys in the secuveri dashboard. Give it Read results, Create sessions and Manage webhooks, plus AML screening or Change lists if you use those. A sk_test_ key works in the sandbox.',
		},
		{
			displayName: 'API URL',
			name: 'baseUrl',
			type: 'string',
			default: 'https://api-verify.secuveri.com',
			description: 'Only change this if secuveri support asks you to',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				'x-api-key': '={{$credentials.apiKey}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.baseUrl}}',
			url: '/v1/verifications',
			qs: { limit: 1 },
		},
	};
}
