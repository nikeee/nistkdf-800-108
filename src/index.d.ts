/**
 * NIST SP800-108 KDF Counter implementation
 * See section 5.1 in https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf
 *
 * @remarks uses HMAC as PRF and BEFORE_FIXED as counter location.
 *
 * @param {number} sizeBytes Required size of the output
 * @param {SupportedHashAlgorithm} hashAlgorithm Hashing algorithm for HMac
 * @param {Buffer} key HMac Key
 * @param {Buffer} label KDF label string. E.g. FDO uses "FDO-KDF" as label
 * @param {Buffer} context KDF context string. E.g. FDO uses "AutomaticOnboardTunnel" as TO2
 * @param {Buffer} [contextRand] Context additional random bytes. Defaults to an empty buffer.
 * @param {CounterBitWidth} [counterWidth] `rLen`. The width of the counter field in bits.
 *
 * @returns {Buffer}
 */
export function counterKdf(
	sizeBytes: number,
	hashAlgorithm: SupportedHashAlgorithm,
	key: Buffer,
	label: Buffer,
	context: Buffer,
	contextRand: Buffer = emptyBuffer,
	counterWidth: CounterBitWidth = 8,
): Buffer;

export type CounterBitWidth = 8 | 16 | 24 | 32;

export type SupportedHashAlgorithm = "sha256" | "sha384";
