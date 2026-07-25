/** biome-ignore-all lint/style/noDefaultExport: explanation */
import LiveCode from '#components/LiveCode.vue' with { type: 'vue' };
import VersionedNav from '#components/VersionedNav.vue' with { type: 'vue' };
import VersionSwitcher from '#components/VersionSwitcher.vue' with { type: 'vue' };
import type { Theme } from 'vitepress';
import DefaultTheme from 'vitepress/theme';
import './custom.css' with { type: 'css' };

const theme: Theme = {
	extends: DefaultTheme,
	enhanceApp({ app }) {
		app.component('LiveCode', LiveCode);
		app.component('VersionedNav', VersionedNav);
		app.component('VersionSwitcher', VersionSwitcher);
	},
};

export default theme;
