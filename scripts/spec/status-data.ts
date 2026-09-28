import { isRecord } from './resource.ts';

export interface RfcStatus {
	readonly number: string;
	readonly title: string;
	readonly status: string;
	readonly updates: readonly string[];
	readonly obsoletes: readonly string[];
	readonly updatedBy: readonly string[];
	readonly obsoletedBy: readonly string[];
}

export interface Erratum {
	readonly id: string;
	readonly number: string;
	readonly status: string;
	readonly type: string;
	readonly section: string;
	readonly url: string;
}

/** Normalize bare numbers and RFC identifiers without accepting unsafe integers. */
export function rfcNumber(input: string): string | undefined {
	const match = /^(?:rfc)?0*([1-9][0-9]*)$/i.exec(input);
	const number = match?.[1];
	return number !== undefined && Number.isSafeInteger(Number(number)) ? number : undefined;
}

function relation(value: unknown): readonly string[] | undefined {
	if (!Array.isArray(value)) return undefined;
	const numbers: string[] = [];
	for (const item of value) {
		if (typeof item !== 'string') return undefined;
		const number = rfcNumber(item);
		if (number === undefined) return undefined;
		numbers.push(number);
	}
	return [...new Set(numbers)].sort((left, right) => Number(left) - Number(right));
}

/** RFC Editor per-document JSON, including the reverse update relationships. */
export function parseRfcStatus(value: unknown, expected: string): RfcStatus | undefined {
	if (!isRecord(value)) return undefined;
	const id = value['doc_id'];
	const title = value['title'];
	const status = value['status'];
	const updates = relation(value['updates']);
	const obsoletes = relation(value['obsoletes']);
	const updatedBy = relation(value['updated_by']);
	const obsoletedBy = relation(value['obsoleted_by']);
	if (
		typeof id !== 'string' || rfcNumber(id) !== expected ||
		typeof title !== 'string' || title.trim() === '' ||
		typeof status !== 'string' || status.trim() === '' ||
		updates === undefined || obsoletes === undefined ||
		updatedBy === undefined || obsoletedBy === undefined
	) return undefined;
	return { number: expected, title, status, updates, obsoletes, updatedBy, obsoletedBy };
}

function erratum(value: unknown): Erratum | undefined {
	if (!isRecord(value)) return undefined;
	const rawId = value['errata_id'];
	const id = typeof rawId === 'number' || typeof rawId === 'string' ? String(rawId) : '';
	const document = value['doc-id'];
	const number = typeof document === 'string' ? rfcNumber(document) : undefined;
	const status = value['errata_status_code'];
	const type = value['errata_type_code'];
	const section = value['section'];
	if (
		!/^[1-9][0-9]*$/.test(id) || !Number.isSafeInteger(Number(id)) ||
		number === undefined || typeof status !== 'string' || status.trim() === '' ||
		typeof type !== 'string' || typeof section !== 'string'
	) return undefined;
	return { id, number, status, type, section, url: `https://www.rfc-editor.org/errata/eid${id}` };
}

/** Preserve Reported, Held, Rejected and unknown statuses; none is an automatic amendment. */
export function parseErrata(value: unknown): readonly Erratum[] | undefined {
	if (!Array.isArray(value) || value.length === 0) return undefined;
	const reports: Erratum[] = [];
	const seen = new Set<string>();
	for (const item of value) {
		const report = erratum(item);
		if (report === undefined || seen.has(report.id)) return undefined;
		seen.add(report.id);
		reports.push(report);
	}
	return reports.sort((left, right) => Number(left.id) - Number(right.id));
}
