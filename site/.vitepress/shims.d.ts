declare module '*.css' {
	const stylesheet: CSSStyleSheet;
	export default stylesheet;
}

declare module 'markdown-it-task-lists' {
	import type { PluginSimple } from 'markdown-it';
	const taskLists: PluginSimple;
	export default taskLists;
}

declare module '*.vue' {
	import type { DefineComponent } from 'vue';
	const component: DefineComponent;
	export default component;
}
