export interface SourceDiagnostic {
	readonly code: 'BROKEN_REFERENCE' | 'SPARSE_PDF_PAGE';
	readonly line: number | undefined;
	readonly page: number | undefined;
	readonly message: string;
}

/** Flag missing evidence; never manufacture replacement clause numbers or OCR text. */
export function sourceDiagnostics(source: string, pdf = false): readonly SourceDiagnostic[] {
	const diagnostics: SourceDiagnostic[] = [];
	for (const [index, text] of source.split('\n').entries()) {
		if (/Error[!:]?\s*(?:Reference source not found|Bookmark not defined)/i.test(text)) {
			diagnostics.push({
				code: 'BROKEN_REFERENCE',
				line: index + 1,
				page: undefined,
				message:
					'Unresolved source cross-reference; inspect the original document before citing it.',
			});
		}
	}
	if (pdf) {
		const pages = source.split('\f');
		if (pages.at(-1)?.trim() === '') pages.pop();
		for (const [index, text] of pages.entries()) {
			if ((text.match(/\p{L}/gu)?.length ?? 0) < 40)
				diagnostics.push({
					code: 'SPARSE_PDF_PAGE',
					line: undefined,
					page: index + 1,
					message:
						'Little extractable text; this page may contain a scan or image-only table. Inspect the retained PDF.',
				});
		}
	}
	return diagnostics;
}
