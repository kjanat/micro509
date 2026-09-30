import { createRequire } from 'node:module';
import { run } from 'vue-tsc';

const require = createRequire(import.meta.url);

// Select the native checker explicitly even when vue-tsc is hoisted beside TS6.
run(require.resolve('typescript-native-bridge/lib/tsc'));
