declare module '*.css' {
	const stylesheet: CSSStyleSheet;
	export default stylesheet;
}

declare module '*.vue' {
	import type { DefineComponent } from 'vue';
	const component: DefineComponent;
	export default component;
}
