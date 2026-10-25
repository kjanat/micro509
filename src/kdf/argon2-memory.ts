interface MatrixPool {
	readonly take: (words: number) => Uint32Array<ArrayBuffer>;
	readonly release: (matrix: Uint32Array<ArrayBuffer>) => void;
}

/** Reuse wiped matrices without preventing garbage collection of idle storage. */
export function createMatrixPool(): MatrixPool {
	const idle: WeakRef<Uint32Array<ArrayBuffer>>[] = [];
	return {
		take(words) {
			for (let index = idle.length - 1; index >= 0; index -= 1) {
				const matrix = idle[index]?.deref();
				if (matrix === undefined || matrix.length === words) {
					idle.splice(index, 1);
					if (matrix !== undefined) return matrix;
				}
			}
			return new Uint32Array(words);
		},
		release(matrix) {
			matrix.fill(0);
			if (matrix.length === 0) return;
			if (idle.length === 4) idle.shift();
			idle.push(new WeakRef(matrix));
		},
	};
}
