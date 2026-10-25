/** Format console arguments with multiline values on their own lines. */
export function formatConsoleArgs(args: readonly unknown[]): string {
	const values = args.map((value) =>
		typeof value === 'string' ? value : (JSON.stringify(value, null, 2) ?? String(value)),
	);
	return values.reduce((output, value, index) => {
		if (index === 0) return value;
		const previous = values[index - 1] ?? '';
		if (previous.endsWith('\n') || value.startsWith('\n')) return output + value;
		const separator = previous.includes('\n') || value.includes('\n') ? '\n' : ' ';
		return output + separator + value;
	}, '');
}
