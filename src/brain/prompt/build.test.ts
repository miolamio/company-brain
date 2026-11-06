import { describe, expect, it } from "vitest"
import { BARE_MENTION_QUESTION, questionForMessage } from "./build"

describe("questionForMessage", () => {
	it("answers a bare mention instead of dropping it", () => {
		expect(questionForMessage("<@U123>", true)).toBe(BARE_MENTION_QUESTION)
		expect(questionForMessage("  <@U123>  <@U456> ", true)).toBe(
			BARE_MENTION_QUESTION,
		)
	})

	it("keeps the real text when there is any", () => {
		expect(questionForMessage("<@U123> what is up", true)).toBe("what is up")
	})

	it("still drops an empty message that is not a mention", () => {
		expect(questionForMessage("", false)).toBe("")
		expect(questionForMessage(undefined, false)).toBe("")
		expect(questionForMessage("<@U123>", false)).toBe("")
	})
})
