// @ts-check
/// <reference lib="es2024" />

import { describe, it } from "node:test";
import { expect } from "expect";

import {
	counterKbkdfAfterFixedCounter,
	counterKbkdfBeforeFixedCounter,
	counterKbkdfMiddleFixedCounter,
} from "./counter.js";

// Some test vectors taken from CAVP testing for SP 800-108
// Ref: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/key-derivation
import testVector from "./counter.test.json" with { type: "json" };

describe("counting KBKDF", async () => {
	const byPrf = Object.groupBy(testVector, e => e.prf);

	describe("hmac-sha256", async () => {
		const byCounterLocation = Object.groupBy(
			// @ts-expect-error
			byPrf.HMAC_SHA256,
			e => e.counterLocation,
		);

		describe("counter before fixed data", async () => {
			const byRLen = Object.groupBy(
				// @ts-expect-error
				byCounterLocation.BEFORE_FIXED,
				e => e.rLen,
			);

			expect(byCounterLocation.BEFORE_FIXED?.length).toBeGreaterThan(0);
			expect(Object.keys(byRLen)).toStrictEqual(["8", "16", "24", "32"]);

			expect(Object.keys(byRLen).length).toBe(4);
			for (const [counterWidth, suites] of Object.entries(byRLen)) {
				it(`${counterWidth} bit r length`, async () => {
					expect(suites?.length).toBe(1);
					// @ts-expect-error
					for (const suite of suites) {
						expect(suite.tests.length).toBe(40);
						for (const test of suite.tests) {
							const n = test.COUNT + 1;

							const ki = Buffer.from(test.KI, "hex");
							// @ts-expect-error
							const fixedInputData = Buffer.from(test.FixedInputData, "hex");
							const koExpected = Buffer.from(test.KO, "hex");

							const keyOutSize = koExpected.length;
							const ko = counterKbkdfBeforeFixedCounter(
								"sha256",
								ki,
								fixedInputData,
								keyOutSize,
								// @ts-expect-error
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
				// @ts-expect-error
				byCounterLocation.AFTER_FIXED,
				e => e.rLen,
			);

			expect(byCounterLocation.AFTER_FIXED?.length).toBeGreaterThan(0);
			expect(Object.keys(byRLen)).toStrictEqual(["8", "16", "24", "32"]);

			expect(Object.keys(byRLen).length).toBe(4);
			for (const [counterWidth, suites] of Object.entries(byRLen)) {
				it(`${counterWidth} bit r length`, async () => {
					expect(suites?.length).toBe(1);
					// @ts-expect-error
					for (const suite of suites) {
						expect(suite.tests.length).toBe(40);
						for (const test of suite.tests) {
							const n = test.COUNT + 1;

							const ki = Buffer.from(test.KI, "hex");
							// @ts-expect-error
							const fixedInputData = Buffer.from(test.FixedInputData, "hex");
							const koExpected = Buffer.from(test.KO, "hex");

							const keyOutSize = koExpected.length;
							const ko = counterKbkdfAfterFixedCounter(
								"sha256",
								ki,
								fixedInputData,
								keyOutSize,
								// @ts-expect-error
								/** @type {8|16|24|32} */ Number(counterWidth),
								n,
							);

							expect(ko).toStrictEqual(koExpected);
						}
					}
				});
			}
		});

		describe("counter middle fixed data", async () => {
			const byRLen = Object.groupBy(
				// @ts-expect-error
				byCounterLocation.MIDDLE_FIXED,
				e => e.rLen,
			);

			expect(byCounterLocation.MIDDLE_FIXED?.length).toBeGreaterThan(0);
			expect(Object.keys(byRLen)).toStrictEqual(["8", "16", "24", "32"]);

			expect(Object.keys(byRLen).length).toBe(4);
			for (const [counterWidth, suites] of Object.entries(byRLen)) {
				it(`${counterWidth} bit r length`, async () => {
					expect(suites?.length).toBe(1);
					// @ts-expect-error
					for (const suite of suites) {
						expect(suite.tests.length).toBe(40);
						for (const test of suite.tests) {
							const n = test.COUNT + 1;

							const ki = Buffer.from(test.KI, "hex");
							const fixedInputBefore = Buffer.from(
								// @ts-expect-error
								test.DataBeforeCtrData,
								"hex",
							);
							// @ts-expect-error
							const fixedInputAfter = Buffer.from(test.DataAfterCtrData, "hex");
							const koExpected = Buffer.from(test.KO, "hex");

							const keyOutSize = koExpected.length;
							const ko = counterKbkdfMiddleFixedCounter(
								"sha256",
								ki,
								fixedInputBefore,
								fixedInputAfter,
								keyOutSize,
								// @ts-expect-error
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
