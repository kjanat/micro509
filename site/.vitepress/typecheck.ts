import path from 'node:path';
import { checkProjectSync, formatDiagnostic } from '@kjanat/tsc-bridge';

const root = import.meta.dirname;
const diagnostics = checkProjectSync(path.join(root, 'tsconfig.json'), { runExternalCode: true });
for (const diagnostic of diagnostics) console.log(formatDiagnostic(diagnostic, root));
if (diagnostics.some((diagnostic) => diagnostic.category === 1)) process.exitCode = 2;
