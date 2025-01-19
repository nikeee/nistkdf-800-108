// @ts-check

import { counterKbkdfBeforeFixedCounter } from "./counter.js";
import { availableHashes } from "./hashes.js";

const emptyBuffer = Buffer.alloc(0);

/**
 * NIST SP800-108 KDF Counter implementation
 * See section 5.1 in https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf
 *
 * @remarks uses HMAC as PRF and BEFORE_FIXED as counter location.
 *
 * @param {number} sizeBytes Required size of the output
 * @param {import("./index.js").SupportedHashAlgorithm} hashAlgorithm Hashing algorithm for HMac
 * @param {Buffer} key HMac Key
 * @param {Buffer} label KDF label string. E.g. FDO uses "FDO-KDF" as label
 * @param {Buffer} context KDF context string. E.g. FDO uses "AutomaticOnboardTunnel" as TO2
 * @param {Buffer} [contextRand] Context additional random bytes. Defaults to an empty buffer.
 * @param {import("./index.js").CounterBitWidth} [counterWidth] `rLen`. The width of the counter field in bits.
 *
 * @returns {Buffer}
 *
 * @__PURE__
 */
export function counterKdf(
	sizeBytes,
	hashAlgorithm,
	key,
	label,
	context,
	contextRand = emptyBuffer,
	counterWidth = 8,
) {
	const hashInfo = availableHashes[hashAlgorithm];
	if (!hashInfo) {
		throw new Error(`Unsupported hashAlgorithm: "${hashAlgorithm}"`);
	}

	const h = hashInfo.lenBits;
	const l = sizeBytes * 8;

	const n = Math.ceil(l / h);

	// > In the following key-derivation
	// > functions, the fixed input data is a concatenation of a Label, a separation indicator 0x00, the
	// > Context, and [L]2."
	// Section 4 in NIST.SP.800-108r1-upd1
	const fixedInputData = Buffer.concat([
		label,
		Buffer.alloc(1),
		context,
		contextRand,
		Buffer.from([(l >> 8) & 0xff, l & 0xff]),
	]);

	return counterKbkdfBeforeFixedCounter(
		hashAlgorithm,
		key,
		fixedInputData,
		sizeBytes,
		counterWidth,
		n,
	);
}
