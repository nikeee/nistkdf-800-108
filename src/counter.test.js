// @ts-check
/// <reference lib="es2024" />

import { describe, it } from "node:test";
import { expect } from "expect";

import {
	counterKbkdfAfterFixedCounter,
	counterKbkdfBeforeFixedCounter,
} from "./counter.js";

// Some test vectors taken from CAVP testing for SP 800-108
// Ref: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/key-derivation
import testVector from "./counter.test.json" with { type: "json" };

describe("counting KBKDF", async () => {
	const byPrf = Object.groupBy(testVector, e => e.prf);

	describe("hmac-sha256", async () => {
		const byCounterLocation = Object.groupBy(
			// @ts-ignore
			byPrf.HMAC_SHA256,
			e => e.counterLocation,
		);

		describe("counter before fixed data", async () => {
			const byRLen = Object.groupBy(
				// @ts-ignore
				byCounterLocation.BEFORE_FIXED,
				e => e.rLen,
			);

			for (const [counterWidth, suites] of Object.entries(byRLen)) {
				it(`${counterWidth} bit r length`, async () => {
					// @ts-ignore
					for (const suite of suites) {
						for (const test of suite.tests) {
							const n = test.COUNT + 1;

							const ki = Buffer.from(test.KI, "hex");
							// @ts-ignore
							const fixedInputData = Buffer.from(test.FixedInputData, "hex");
							const koExpected = Buffer.from(test.KO, "hex");

							const keyOutSize = koExpected.length;
							const ko = counterKbkdfBeforeFixedCounter(
								"sha256",
								ki,
								fixedInputData,
								keyOutSize,
								// @ts-ignore
								/** @type {8|16|24|32} */ Number(counterWidth),
								n,
							);

							expect(ko).toStrictEqual(koExpected);
						}
					}
				});
			}
		});

		describe("counter after fixed data", async () => {
			const byRLen = Object.groupBy(
				// @ts-ignore
				byCounterLocation.AFTER_FIXED,
				e => e.rLen,
			);

			for (const [counterWidth, suites] of Object.entries(byRLen)) {
				it(`${counterWidth} bit r length`, async () => {
					// @ts-ignore
					for (const suite of suites) {
						for (const test of suite.tests) {
							const n = test.COUNT + 1;

							const ki = Buffer.from(test.KI, "hex");
							// @ts-ignore
							const fixedInputData = Buffer.from(test.FixedInputData, "hex");
							const koExpected = Buffer.from(test.KO, "hex");

							const keyOutSize = koExpected.length;
							const ko = counterKbkdfAfterFixedCounter(
								"sha256",
								ki,
								fixedInputData,
								keyOutSize,
								// @ts-ignore
								/** @type {8|16|24|32} */ Number(counterWidth),
								n,
							);

							expect(ko).toStrictEqual(koExpected);
						}
					}
				});
			}
		});
	});
});
