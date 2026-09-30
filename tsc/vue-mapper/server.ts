import { closeProject, openProject, transform, verify } from './mapper.ts';
import { serve } from './rpc.ts';

serve((method, params) => {
	switch (method) {
		case 'initialize':
			return { positionEncoding: 'utf-16', diagnosticSource: 'vue' };
		case 'openProject':
			return openProject(params);
		case 'closeProject':
			return closeProject(params);
		case 'transform':
			return transform(params);
		case 'verify':
			return verify(params);
		default:
			throw new Error(`Unknown method: ${method}`);
	}
});
