import type { SourceLine } from './types.ts';

const BYTE_ORDER_MARK = '﻿';
const FORM_FEED = '\f';
const REPLACEMENT = /�/g;

export interface StrippedText {
	readonly lines: readonly SourceLine[];
	readonly seams: ReadonlySet<number>;
}

export interface Block {
	readonly lines: readonly SourceLine[];
	readonly seamBefore: boolean;
}

export function sourceLines(source: string): readonly SourceLine[] {
	const body = source.startsWith(BYTE_ORDER_MARK) ? source.slice(BYTE_ORDER_MARK.length) : source;
	return body.split('\n').map((text, index) => ({
		line: index + 1,
		text: text.endsWith('\r') ? text.slice(0, -1) : text,
	}));
}

export function cleanTitle(text: string): string {
	return text.replace(REPLACEMENT, '').replace(/\s+/g, ' ').trim();
}

export function indentOf(text: string): number {
	return text.length - text.trimStart().length;
}

export function joinWrapped(texts: readonly string[]): string {
	return texts
		.map((text) => text.trim())
		.reduce((joined, text) => {
			if (joined === '') return text;
			if (joined.endsWith('-') && /^[a-z]/.test(text)) return `${joined}${text}`;
			return /[.?!]["')\]]?$/.test(joined) ? `${joined}  ${text}` : `${joined} ${text}`;
		}, '');
}

interface FeedSplit {
	readonly lines: readonly SourceLine[];
	readonly breaks: readonly number[];
}

function splitFormFeeds(input: readonly SourceLine[]): FeedSplit {
	const lines: SourceLine[] = [];
	const breaks: number[] = [];
	for (const entry of input) {
		const feed = entry.text.lastIndexOf(FORM_FEED);
		if (feed === -1) {
			lines.push(entry);
			continue;
		}
		breaks.push(lines.length);
		lines.push({ line: entry.line, text: entry.text.slice(feed + 1) });
	}
	return { lines, breaks };
}

function runningForm(text: string): string {
	return text.trim().replace(/\s+/g, ' ').replace(/\d+/g, '#');
}

function firstContent(
	lines: readonly SourceLine[],
	start: number,
	end: number,
): number | undefined {
	for (let index = start; index < end; index += 1) {
		if ((lines[index]?.text ?? '').trim() !== '') return index;
	}
	return undefined;
}

function lastContent(lines: readonly SourceLine[], start: number, end: number): number | undefined {
	for (let index = end - 1; index >= start; index -= 1) {
		if ((lines[index]?.text ?? '').trim() !== '') return index;
	}
	return undefined;
}

function tally(counts: Map<string, number>, key: string): void {
	counts.set(key, (counts.get(key) ?? 0) + 1);
}

interface PageSpan {
	readonly start: number;
	readonly end: number;
}

function pageSpans(lineCount: number, breaks: readonly number[]): readonly PageSpan[] {
	const starts = [0, ...breaks];
	return starts
		.map((start, position) => ({ start, end: starts[position + 1] ?? lineCount }))
		.filter((span) => span.end > span.start);
}

function furnitureIndices(
	lines: readonly SourceLine[],
	breaks: readonly number[],
): ReadonlySet<number> {
	const spans = pageSpans(lines.length, breaks);
	const headerCounts = new Map<string, number>();
	const footerCounts = new Map<string, number>();
	for (const span of spans) {
		const head = firstContent(lines, span.start, span.end);
		const foot = lastContent(lines, span.start, span.end);
		if (head !== undefined) tally(headerCounts, runningForm(lines[head]?.text ?? ''));
		if (foot !== undefined && foot !== head)
			tally(footerCounts, runningForm(lines[foot]?.text ?? ''));
	}
	const needed = Math.max(3, Math.ceil(spans.length / 4));
	const dropped = new Set<number>();
	for (const span of spans) {
		const head = firstContent(lines, span.start, span.end);
		const foot = lastContent(lines, span.start, span.end);
		if (
			head !== undefined &&
			(headerCounts.get(runningForm(lines[head]?.text ?? '')) ?? 0) >= needed
		) {
			dropped.add(head);
		}
		if (
			foot !== undefined &&
			foot !== head &&
			(footerCounts.get(runningForm(lines[foot]?.text ?? '')) ?? 0) >= needed
		) {
			dropped.add(foot);
		}
	}
	return dropped;
}

function isVoid(
	lines: readonly SourceLine[],
	index: number,
	dropped: ReadonlySet<number>,
): boolean {
	return dropped.has(index) || (lines[index]?.text ?? '').trim() === '';
}

function collapseBreak(
	lines: readonly SourceLine[],
	index: number,
	dropped: Set<number>,
	seams: Set<number>,
): void {
	let high = index - 1;
	if (isVoid(lines, index, dropped)) {
		high = index;
		while (high + 1 < lines.length && isVoid(lines, high + 1, dropped)) high += 1;
	}
	let low = index - 1;
	while (low >= 0 && isVoid(lines, low, dropped)) low -= 1;
	low += 1;
	if (low > high) return;
	let kept: number | undefined;
	for (let cursor = low; cursor <= high; cursor += 1) {
		if (kept === undefined && !dropped.has(cursor)) {
			kept = cursor;
			continue;
		}
		dropped.add(cursor);
	}
	if (kept !== undefined) seams.add(lines[kept]?.line ?? 0);
}

export function stripPageArtifacts(input: readonly SourceLine[]): StrippedText {
	const { lines, breaks } = splitFormFeeds(input);
	if (breaks.length === 0) return { lines, seams: new Set() };
	const dropped = new Set(furnitureIndices(lines, breaks));
	const seams = new Set<number>();
	for (const index of breaks) collapseBreak(lines, index, dropped, seams);
	return { lines: lines.filter((_, index) => !dropped.has(index)), seams };
}

export function blocksOf(
	lines: readonly SourceLine[],
	seams: ReadonlySet<number>,
): readonly Block[] {
	const blocks: Block[] = [];
	let current: SourceLine[] = [];
	let seamPending = false;
	for (const entry of lines) {
		if (entry.text.trim() === '') {
			if (current.length > 0) {
				blocks.push({ lines: current, seamBefore: seamPending });
				current = [];
				seamPending = false;
			}
			if (seams.has(entry.line)) seamPending = true;
			continue;
		}
		current.push(entry);
	}
	if (current.length > 0) blocks.push({ lines: current, seamBefore: seamPending });
	return blocks;
}

export function isProse(block: Block): boolean {
	const base = indentOf(block.lines[0]?.text ?? '');
	for (const entry of block.lines) {
		if (indentOf(entry.text) !== base) return false;
		const body = entry.text.trim();
		if (body.startsWith('|') || body.startsWith('+-') || body.startsWith('--')) return false;
		if (body.includes('::=')) return false;
		if (/\S {3,}\S/.test(body)) return false;
	}
	return true;
}

function continuesParagraph(paragraph: string, block: Block): boolean {
	if (!block.seamBefore || paragraph === '') return false;
	if (/[.:;?!]$/.test(paragraph.trimEnd())) return false;
	return !/^\s*\d+(\.\d+)*\.?\s/.test(block.lines[0]?.text ?? '');
}

export function renderBody(blocks: readonly Block[], dedent: number): readonly string[] {
	const rendered: string[] = [];
	let paragraph = '';
	let margin = '';
	const flush = (): void => {
		if (paragraph === '') return;
		if (rendered.length > 0) rendered.push('');
		rendered.push(`${margin}${paragraph}`);
		paragraph = '';
	};
	for (const block of blocks) {
		if (!isProse(block)) {
			flush();
			if (rendered.length > 0) rendered.push('');
			for (const entry of block.lines) rendered.push(entry.text.slice(dedent).trimEnd());
			continue;
		}
		const joined = joinWrapped(block.lines.map((entry) => entry.text));
		if (continuesParagraph(paragraph, block)) {
			paragraph = joinWrapped([paragraph, joined]);
			continue;
		}
		flush();
		paragraph = joined;
		margin = ' '.repeat(Math.max(0, indentOf(block.lines[0]?.text ?? '') - dedent));
	}
	flush();
	return rendered;
}

export function minimumIndent(lines: readonly SourceLine[]): number {
	let minimum = Number.POSITIVE_INFINITY;
	for (const entry of lines) {
		if (entry.text.trim() === '') continue;
		minimum = Math.min(minimum, indentOf(entry.text));
	}
	return Number.isFinite(minimum) ? minimum : 0;
}
