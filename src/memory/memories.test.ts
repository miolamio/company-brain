import { describe, expect, it } from "vitest"
import { readStringArray } from "./memories"

describe("readStringArray", () => {
	it("drops empty and blank entries from comma lists", () => {
		expect(readStringArray("a,,b")).toEqual(["a", "b"])
		expect(readStringArray(" a , , b ,")).toEqual(["a", "b"])
		expect(readStringArray("  ")).toEqual([])
	})

	it("trims and filters arrays, ignoring non-strings", () => {
		expect(readStringArray([" a ", "", "  ", "b", 3, null])).toEqual(["a", "b"])
	})

	it("returns [] for other values", () => {
		expect(readStringArray(undefined)).toEqual([])
		expect(readStringArray(5)).toEqual([])
	})
})
