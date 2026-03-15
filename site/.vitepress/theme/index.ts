import type { Theme } from 'vitepress';
import DefaultTheme from 'vitepress/theme';
import LiveCode from './components/LiveCode.vue';
// @ts-expect-error
import './custom.css' with { type: 'css' };

export default {
	extends: DefaultTheme,
	enhanceApp({ app }) {
		app.component('LiveCode', LiveCode);
	},
} satisfies Theme;
