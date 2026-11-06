/**
 * Default-deny check for SQL passed to query tools.
 *
 * Why: tools named `query`, `run_query` or `execute_sql` take free-form SQL,
 * and the tool name cannot tell a SELECT from a DELETE. Listing write patterns
 * kept missing variants (T-SQL, MySQL executable comments, side-effect
 * functions), so this works the other way round:
 *
 *   1. Collect every string in the arguments, and look inside strings that
 *      are themselves JSON.
 *   2. A string is "SQL" when it starts with a statement keyword. Prose
 *      ("look into the outage") is ignored.
 *   3. SQL is read-only only when it is exactly one statement, starts with a
 *      read keyword, has no write or danger keyword, and no side-effect
 *      function. Anything else needs approval.
 *
 * Comments and literals are stripped under several readings of the dialect
 * rules (MySQL and Postgres disagree on backslashes, `#`, `$$` and `--`), and
 * the SQL must be read-only under all of them.
 */

/** Name tokens that mark a tool as one that runs caller-supplied SQL. */
const QUERY_TOOL_TOKENS = new Set([
	"query",
	"queries",
	"sql",
	"statement",
	"exec",
	"execute",
	"db",
])

/** A string starting with one of these is treated as SQL. */
const SQL_START_WORDS = new Set([
	"select", "with", "insert", "update", "delete", "merge", "replace", "upsert",
	"create", "drop", "alter", "truncate", "rename", "grant", "revoke", "exec",
	"execute", "call", "copy", "load", "pragma", "set", "reset", "begin", "start",
	"commit", "rollback", "savepoint", "explain", "analyze", "vacuum", "attach",
	"detach", "show", "describe", "desc", "values", "table", "do", "lock", "unlock",
	"handler", "import", "refresh", "cluster", "reindex", "comment", "prepare",
	"deallocate", "listen", "notify", "checkpoint", "discard", "end", "release",
	"use", "declare", "fetch", "move", "close", "security", "abort",
])

/**
 * A lone word is usually a parameter value ("start", "set", "desc"), not a
 * statement. These few are statements on their own.
 */
const BARE_SQL_WORDS = new Set([
	"vacuum", "reindex", "cluster", "analyze", "checkpoint", "commit", "rollback",
	"unlock", "reset", "discard", "begin", "abort", "end",
])

const ID = "[\\w.\"`\\[\\]$]+"
const OBJECTS =
	"(?:or\\s+replace\\s+|temp\\w*\\s+|unique\\s+|materialized\\s+|global\\s+|local\\s+|unlogged\\s+|virtual\\s+|recursive\\s+|foreign\\s+|external\\s+)*(?:table|view|index|database|schema|user|role|function|procedure|trigger|sequence|type|extension|policy|domain|collation|column|constraint|event|server|tablespace|publication|subscription|aggregate|cast|operator|rule|language|group|stage|warehouse|pipe|stream|task|if)\\b"

/**
 * Words that also start ordinary sentences ("update the config to set X").
 * A string starting with one counts as SQL only if it also has the grammar
 * of a statement. Every real statement of that kind matches its shape; the
 * shapes are loose on purpose. Words not listed here count as SQL on the
 * first word alone.
 */
const STATEMENT_SHAPES: Record<string, RegExp> = {
	update: /^update\b[\s\S]*?\bset\b[^=;]*=/i,
	delete: new RegExp(
		`^delete\\s+(?:from\\b|top\\b|${ID}\\s+(?:from|where|using|output|returning|limit|order)\\b|${ID}\\s*;?\\s*$)`,
		"i",
	),
	insert: new RegExp(
		`^insert\\s+(?:(?:low_priority|delayed|high_priority|ignore|or\\s+\\w+)\\s+)*(?:into\\s+)?${ID}\\s*(?:\\(|values\\b|select\\b|default\\b|set\\b|overwrite\\b|partition\\b|with\\b|on\\b|table\\b)`,
		"i",
	),
	drop: new RegExp(`^drop\\s+${OBJECTS}`, "i"),
	alter: new RegExp(`^alter\\s+(?:${OBJECTS}|system\\b|session\\b)`, "i"),
	create: new RegExp(`^create\\s+${OBJECTS}`, "i"),
	truncate: new RegExp(`^truncate\\s+(?:table\\s+)?(?:only\\s+)?${ID}`, "i"),
	set: new RegExp(
		`^set\\s+(?:(?:session|local|global|persist\\w*)\\s+)?(?:${ID}\\s*:?=|${ID}\\s+to\\b|role\\b|session\\s+authorization|transaction\\b|names\\b|constraints\\b|time\\s+zone\\b|search_path\\b)`,
		"i",
	),
	call: new RegExp(`^call\\s+${ID}\\s*\\(`, "i"),
	do: /^do\s+(?:\$|language\b|'|")/i,
	with: new RegExp(`^with\\s+(?:recursive\\s+)?${ID}\\s*(?:\\([^)]*\\))?\\s*as\\b`, "i"),
	begin: /^begin\s*(?:;|$|\s+(?:transaction|tran|work|isolation|read|deferrable|not|immediate|deferred|exclusive))/i,
	start: /^start\s+transaction\b/i,
	lock: /^lock\s+(?:table\b|tables\b|\w+\s+in\b)/i,
	comment: /^comment\s+on\b/i,
	use: new RegExp(`^use\\s+${ID}\\s*;?\\s*$`, "i"),
	end: /^end\s*;?\s*$/i,
	close: new RegExp(`^close\\s+${ID}\\s*;?\\s*$`, "i"),
	move: /^move\s+(?:next|prior|first|last|absolute|relative|forward|backward|all|\d)/i,
	fetch: /^fetch\s+(?:next|prior|first|last|absolute|relative|forward|backward|all|\d)/i,
	release: /^release\s+(?:savepoint\s+)?\w+\s*;?\s*$/i,
	import: /^import\s+(?:foreign\s+schema|into)\b/i,
	refresh: /^refresh\s+materialized\b/i,
	security: /^security\s+label\b/i,
}

const READ_FIRST_WORDS = new Set([
	"select", "with", "show", "describe", "desc", "explain", "values", "table",
])

const WRITE_WORDS = [
	"insert", "update", "delete", "merge", "replace", "upsert", "create", "drop",
	"alter", "truncate", "rename", "grant", "revoke", "exec", "execute", "call",
	"copy", "load", "pragma", "set", "into", "lock", "attach", "detach", "vacuum",
	"analyze", "do", "handler", "import", "refresh", "reindex", "cluster",
	"notify", "listen", "prepare", "deallocate", "unlock", "reset", "savepoint",
	"commit", "rollback", "begin", "checkpoint", "discard",
]
/** Also real scalar functions: `replace(a, b, c)` is fine, `replace t` is not. */
const FUNCTION_LIKE = new Set(["replace", "insert", "truncate"])
const DESTRUCTIVE_WORDS = new Set(["drop", "alter", "truncate"])

const WRITE_WORD_RE = new RegExp(
	`(?<![\\w$.])(${[...WRITE_WORDS, "truncate"].join("|")})(?![\\w$])`,
	"gi",
)
const COMMENT_ON_RE = /(?<![\w$.])comment\s+on(?![\w$])/i
const DANGER_FN_RE =
	/(?<![\w$])(?:dblink\w*|pg_terminate_backend|pg_cancel_backend|lo_\w+|pg_write_file|pg_read_file|pg_read_binary_file|pg_ls_dir|set_config|nextval|setval|pg_sleep\w*|load_file|sys_exec\w*|sys_eval\w*|xp_\w+|sp_\w+|openrowset|opendatasource|bulk)(?![\w$])/i
const FOR_UPDATE_RE = /\bfor\s+(?:no\s+key\s+)?update\b/gi

const MAX_SQL_CHARS = 100_000
const MAX_JSON_CHARS = 1_000_000
const MAX_NODES = 20_000
const MAX_JSON_DEPTH = 6

/** Splits "runQuery" / "execute_sql" / "EXECUTE-SQL" into lowercase words. */
export function nameTokens(name: string): string[] {
	return name
		.replace(/([a-z0-9])([A-Z])/g, "$1 $2")
		.replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
		.toLowerCase()
		.split(/[^a-z0-9]+/)
		.filter(Boolean)
}

export function isQueryTool(toolName: string): boolean {
	return nameTokens(toolName).some((token) => QUERY_TOOL_TOKENS.has(token))
}

interface Reading {
	backslash: boolean
	hash: boolean
	dollar: boolean
	bracket: boolean
	dashNeedsSpace: boolean
}

const READINGS: Reading[] = []
for (let mask = 0; mask < 32; mask++) {
	READINGS.push({
		backslash: Boolean(mask & 1),
		hash: Boolean(mask & 2),
		dollar: Boolean(mask & 4),
		bracket: Boolean(mask & 8),
		dashNeedsSpace: Boolean(mask & 16),
	})
}

/**
 * Removes comments and quoted text in one left-to-right pass (order matters:
 * `'a--b'; DELETE ...` is a string followed by a statement). Quoted
 * identifiers become the word `x`, strings become `''`.
 */
function strip(sql: string, r: Reading): string {
	let out = ""
	let i = 0
	const n = sql.length
	while (i < n) {
		const ch = sql[i] as string
		const next = sql[i + 1]
		if (
			ch === "-" &&
			next === "-" &&
			(!r.dashNeedsSpace || i + 2 >= n || /[\s\x00-\x1f]/.test(sql[i + 2] as string))
		) {
			const end = sql.indexOf("\n", i)
			i = end === -1 ? n : end
			out += " "
		} else if (ch === "#" && r.hash) {
			const end = sql.indexOf("\n", i)
			i = end === -1 ? n : end
			out += " "
		} else if (ch === "/" && next === "*") {
			const end = sql.indexOf("*/", i + 2)
			i = end === -1 ? n : end + 2
			out += " "
		} else if (ch === "'" || ch === '"' || ch === "`") {
			let j = i + 1
			while (j < n) {
				if (r.backslash && sql[j] === "\\") j += 2
				else if (sql[j] === ch && sql[j + 1] === ch) j += 2
				else if (sql[j] === ch) break
				else j += 1
			}
			i = j + 1
			out += ch === "'" ? "''" : "x"
		} else if (ch === "[" && r.bracket) {
			const end = sql.indexOf("]", i + 1)
			i = end === -1 ? n : end + 1
			out += "x"
		} else if (ch === "$" && r.dollar && !(i > 0 && /[\w$]/.test(sql[i - 1] as string))) {
			const tag = /^\$[A-Za-z_]*\$/.exec(sql.slice(i, i + 200))
			const end = tag ? sql.indexOf(tag[0], i + tag[0].length) : -1
			if (tag) {
				i = end === -1 ? n : end + tag[0].length
				out += "''"
			} else {
				out += ch
				i += 1
			}
		} else {
			out += ch
			i += 1
		}
	}
	return out
}

/** Strips leading whitespace, comments, `(` and `;`, returning the rest. */
function stripLeading(text: string): string {
	let s = text
	for (let guard = 0; guard < 10_000; guard++) {
		const trimmed = s.replace(/^[\s;(]+/, "")
		if (trimmed.startsWith("--") || trimmed.startsWith("#")) {
			const end = trimmed.indexOf("\n")
			s = end === -1 ? "" : trimmed.slice(end)
		} else if (trimmed.startsWith("/*")) {
			const end = trimmed.indexOf("*/", 2)
			s = end === -1 ? "" : trimmed.slice(end + 2)
		} else {
			return trimmed
		}
	}
	return s
}

/** The statement keyword a string starts with, or undefined if it is not SQL-like. */
function startWord(text: string): string | undefined {
	const rest = stripLeading(text)
	const match = /^([A-Za-z_]+)(?![\w$])/.exec(rest)
	if (!match) return undefined
	const word = (match[1] as string).toLowerCase()
	if (!SQL_START_WORDS.has(word)) return undefined
	if (/^[A-Za-z_]+\s*;?\s*$/.test(rest)) return BARE_SQL_WORDS.has(word) ? word : undefined
	return word
}

type Verdict = "read" | "write" | "destructive"

/** Judges one comment-and-literal-free reading of the SQL. */
function judge(text: string): Verdict {
	let verdict: Verdict = "read"
	const bump = (v: Verdict) => {
		if (v === "destructive" || verdict === "read") verdict = v
	}
	const segments = text.split(";").filter((s) => s.trim() !== "")
	if (segments.length !== 1) bump("write")
	const first = /^[\s(]*([A-Za-z_]+)/.exec(text)?.[1]?.toLowerCase()
	if (!first || !READ_FIRST_WORDS.has(first)) bump("write")
	const body = text.replace(FOR_UPDATE_RE, " ")
	for (const m of body.matchAll(WRITE_WORD_RE)) {
		const word = (m[1] as string).toLowerCase()
		const after = body.slice((m.index ?? 0) + word.length)
		if (FUNCTION_LIKE.has(word) && /^\s*\(/.test(after)) continue
		bump(DESTRUCTIVE_WORDS.has(word) ? "destructive" : "write")
	}
	if (COMMENT_ON_RE.test(body) || DANGER_FN_RE.test(body)) bump("write")
	return verdict
}

/** Classifies one SQL string: read, write, or destructive (drop/alter/truncate). */
export function classifySql(sql: string, requireShape = false): Verdict {
	try {
		if (sql.length > MAX_SQL_CHARS || /\/\*M?!/.test(sql)) return "write"
		const shape = requireShape ? STATEMENT_SHAPES[startWord(sql) ?? ""] : undefined
		const texts = READINGS.map((reading) => strip(sql, reading))
		if (shape && !texts.some((t) => shape.test(stripLeading(t)))) return "read"
		let result: Verdict = "read"
		for (const text of texts) {
			const v = judge(text)
			if (v === "destructive") return "destructive"
			if (v === "write") result = "write"
		}
		return result
	} catch {
		return "write"
	}
}

export function sqlContainsDdl(sql: string): boolean {
	return classifySql(sql) === "destructive"
}

export function sqlContainsDml(sql: string): boolean {
	return classifySql(sql) === "write"
}

function parseJsonContainer(text: string): unknown {
	const trimmed = text.trim()
	if (trimmed.length > MAX_JSON_CHARS) return undefined
	if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) return undefined
	try {
		const parsed: unknown = JSON.parse(trimmed)
		return parsed && typeof parsed === "object" ? parsed : undefined
	} catch {
		return undefined
	}
}

/**
 * Judges every SQL-looking string in the arguments, including inside JSON
 * strings. Stops early on the first destructive hit. Returns "write" when
 * the traversal budget runs out, so a huge argument cannot hide a statement.
 */
export function classifySqlInput(input: unknown): Verdict {
	let result: Verdict = "read"
	const stack: { value: unknown; jsonDepth: number }[] = [{ value: input, jsonDepth: 0 }]
	let visited = 0
	while (stack.length) {
		const { value, jsonDepth } = stack.pop() as { value: unknown; jsonDepth: number }
		if (++visited > MAX_NODES) return "write"
		if (typeof value === "string") {
			if (startWord(value)) {
				const v = classifySql(value, true)
				if (v === "destructive") return v
				if (v === "write") result = "write"
			}
			if (jsonDepth < MAX_JSON_DEPTH) {
				const parsed = parseJsonContainer(value)
				if (parsed !== undefined) stack.push({ value: parsed, jsonDepth: jsonDepth + 1 })
			} else if (parseJsonContainer(value) !== undefined) {
				return "write"
			}
		} else if (Array.isArray(value)) {
			for (const item of value) stack.push({ value: item, jsonDepth })
		} else if (value && typeof value === "object") {
			for (const item of Object.values(value)) stack.push({ value: item, jsonDepth })
		}
	}
	return result
}

function safeClassifyInput(toolName: string, input: unknown): Verdict {
	if (!isQueryTool(toolName)) return "read"
	try {
		return classifySqlInput(input)
	} catch {
		return "write"
	}
}

/** True when a query tool is being asked to run SQL that is not provably read-only (and not DDL). */
export function queryToolCallHasDml(toolName: string, input: unknown): boolean {
	return safeClassifyInput(toolName, input) === "write"
}

/** True when a query tool is being asked to drop, alter or truncate. */
export function queryToolCallHasDdl(toolName: string, input: unknown): boolean {
	return safeClassifyInput(toolName, input) === "destructive"
}
