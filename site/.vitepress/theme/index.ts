import type { Theme } from 'vitepress';
import DefaultTheme from 'vitepress/theme';
import LiveCode from '#/components/LiveCode.vue' with { type: 'vue' };
import './custom.css' with { type: 'css' };

export const theme: Theme = {
	extends: DefaultTheme,
	enhanceApp({ app }) {
		app.component('LiveCode', LiveCode);
	},
};
