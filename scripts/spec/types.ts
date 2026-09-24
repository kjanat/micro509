export type DocKind = 'rfc' | 'pkits' | 'itu' | 'w3c';

export interface SourceLine {
	readonly line: number;
	readonly text: string;
}

export interface Heading {
	readonly number: string;
	readonly title: string;
	readonly depth: number;
	readonly line: number;
	readonly index: number;
}

export interface RfcMeta {
	readonly kind: 'rfc';
	readonly title: string;
	readonly number: number;
	readonly stream: string | undefined;
	readonly date: string | undefined;
	readonly category: string | undefined;
	readonly issn: string | undefined;
	readonly updates: readonly number[];
	readonly obsoletes: readonly number[];
}

export interface PkitsMeta {
	readonly kind: 'pkits';
	readonly title: string;
	readonly version: string | undefined;
	readonly date: string | undefined;
}

export type ItuVariant = 'base' | 'corrigendum' | 'amendment' | 'erratum' | 'other';

export interface ItuMeta {
	readonly kind: 'itu';
	readonly title: string;
	readonly recommendation: string;
	readonly edition: string | undefined;
	readonly variant: ItuVariant;
	readonly variantNumber: number | undefined;
}

export interface W3cMeta {
	readonly kind: 'w3c';
	readonly title: string;
	readonly status: string | undefined;
	readonly date: string | undefined;
}

export type DocumentMeta = RfcMeta | PkitsMeta | ItuMeta | W3cMeta;

export interface DocumentRef {
	readonly id: string;
	readonly kind: DocKind;
	readonly path: string;
	readonly relativePath: string;
}

export interface ParsedDocument {
	readonly meta: DocumentMeta;
	readonly lines: readonly SourceLine[];
	readonly seams: ReadonlySet<number>;
	readonly headings: readonly Heading[];
}

export interface SpecDocument extends ParsedDocument {
	readonly id: string;
	readonly kind: DocKind;
	readonly relativePath: string;
}
