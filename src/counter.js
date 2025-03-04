// @ts-check
import { createHmac } from "node:crypto";

import { availableHashes } from "./hashes.js";

// Methods are duplicated because:
// - We want to avoid branching inside them
// - We want to avoid logic + indirection to support multiple methods in the same function body
// - Bundlers could tree-shake the unused ones away
// - Node.js doesn't care

/**
 * @type {Record<number, (i: number) => Buffer>}
 */
const counterSizes = /* @__PURE__ */ {
	8: i => Buffer.from([0xff & i]),
	16: i => Buffer.from([(i >> 8) & 0xff, (i >> 0) & 0xff]),
	24: i => Buffer.from([(i >> 16) & 0xff, (i >> 8) & 0xff, (i >> 0) & 0xff]),
	32: i =>
		Buffer.from([
			(i >> 24) & 0xff,
			(i >> 16) & 0xff,
			(i >> 8) & 0xff,
			(i >> 0) & 0xff,
		]),
};

/**
 * @param {import("./index.js").SupportedHashAlgorithm} hashAlgorithm
 * @param {Buffer} keyIn
 * @param {Buffer} fixedInputData
 * @param {number} keyOutSizeInBytes
 * @param {import("./index.js").CounterBitWidth} counterWidth
 * @param {number} n
 *
 * @internal Only exported for testing purposes
 *
 * @__PURE__
 */
export function counterKbkdfBeforeFixedCounter(
	hashAlgorithm,
	keyIn,
	fixedInputData,
	keyOutSizeInBytes,
	counterWidth,
	n,
) {
	if (
		typeof hashAlgorithm !== "string" ||
		!Object.hasOwn(availableHashes, hashAlgorithm)
	) {
		throw new Error(`Unsupported hashAlgorithm: "${hashAlgorithm}"`);
	}

	const counterGenerator = counterSizes[counterWidth];
	if (typeof counterWidth !== "number" || !counterGenerator) {
		throw new Error(`Unsupported counterWidth: ${counterWidth}`);
	}

	if (n > 2 ** counterWidth - 1) {
		throw new Error("Iteration count is too high");
	}

	let resultBuffer = Buffer.alloc(0);
	for (let i = 1; i <= n; ++i) {
		const mac = createHmac(hashAlgorithm, keyIn);

		mac.update(counterGenerator(i));
		mac.update(fixedInputData);

		resultBuffer = Buffer.concat([resultBuffer, mac.digest()]);
	}
	return resultBuffer.subarray(0, keyOutSizeInBytes);
}

/**
 * @param {import("./index.js").SupportedHashAlgorithm} hashAlgorithm
 * @param {Buffer} keyIn
 * @param {Buffer} fixedInputData
 * @param {number} keyOutSizeInBytes
 * @param {import("./index.js").CounterBitWidth} counterWidth
 * @param {number} n
 *
 * @internal Only exported for testing purposes
 *
 * @__PURE__
 */
export function counterKbkdfAfterFixedCounter(
	hashAlgorithm,
	keyIn,
	fixedInputData,
	keyOutSizeInBytes,
	counterWidth,
	n,
) {
	if (
		typeof hashAlgorithm !== "string" ||
		!Object.hasOwn(availableHashes, hashAlgorithm)
	) {
		throw new Error(`Unsupported hashAlgorithm: "${hashAlgorithm}"`);
	}

	const counterGenerator = counterSizes[counterWidth];
	if (typeof counterWidth !== "number" || !counterGenerator) {
		throw new Error(`Unsupported counterWidth: ${counterWidth}`);
	}

	if (n > 2 ** counterWidth - 1) {
		throw new Error("Iteration count is too high");
	}

	let resultBuffer = Buffer.alloc(0);
	for (let i = 1; i <= n; ++i) {
		const mac = createHmac(hashAlgorithm, keyIn);

		mac.update(fixedInputData);
		mac.update(counterGenerator(i));

		resultBuffer = Buffer.concat([resultBuffer, mac.digest()]);
	}
	return resultBuffer.subarray(0, keyOutSizeInBytes);
}

/**
 * @param {import("./index.js").SupportedHashAlgorithm} hashAlgorithm
 * @param {Buffer} keyIn
 * @param {Buffer} fixedInputBeforeCounter
 * @param {Buffer} fixedInputAfterCounter
 * @param {number} keyOutSizeInBytes
 * @param {import("./index.js").CounterBitWidth} counterWidth
 * @param {number} n
 *
 * @internal Only exported for testing purposes
 *
 * @__PURE__
 */
export function counterKbkdfMiddleFixedCounter(
	hashAlgorithm,
	keyIn,
	fixedInputBeforeCounter,
	fixedInputAfterCounter,
	keyOutSizeInBytes,
	counterWidth,
	n,
) {
	if (
		typeof hashAlgorithm !== "string" ||
		!Object.hasOwn(availableHashes, hashAlgorithm)
	) {
		throw new Error(`Unsupported hashAlgorithm: "${hashAlgorithm}"`);
	}

	const counterGenerator = counterSizes[counterWidth];
	if (typeof counterWidth !== "number" || !counterGenerator) {
		throw new Error(`Unsupported counterWidth: ${counterWidth}`);
	}

	if (n > 2 ** counterWidth - 1) {
		throw new Error("Iteration count is too high");
	}

	let resultBuffer = Buffer.alloc(0);
	for (let i = 1; i <= n; ++i) {
		const mac = createHmac(hashAlgorithm, keyIn);

		mac.update(fixedInputBeforeCounter);
		mac.update(counterGenerator(i));
		mac.update(fixedInputAfterCounter);

		resultBuffer = Buffer.concat([resultBuffer, mac.digest()]);
	}
	return resultBuffer.subarray(0, keyOutSizeInBytes);
}
