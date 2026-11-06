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
 *   2. A string is "SQL" when its first word (after whitespace, invisible
 *      characters, comments and opening parentheses) is a known statement
 *      keyword of any common dialect. Prose that starts with anything else
 *      ("look into the outage") is ignored. There is no grammar check on
 *      top: a string that starts with a SQL keyword is judged as SQL, so
 *      prose that starts with one ("update the config") needs approval.
 *   3. SQL is read-only only when it is exactly one statement, starts with a
 *      read keyword, has no other statement keyword anywhere outside literals
 *      and quoted identifiers (this closes T-SQL batches without `;` and
 *      CTE writes), and calls no side-effect function. Anything else needs
 *      approval, and so does any error or limit hit.
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

const words = (list: string) => list.split(/\s+/).filter(Boolean)

const READ_FIRST_WORDS = new Set(
	words("select with show describe desc explain values table"),
)

/**
 * Statement keywords of Postgres, MySQL/MariaDB, SQLite, T-SQL, ClickHouse,
 * Snowflake, BigQuery, DuckDB, Spark and HogQL, minus the read set. One of
 * these as a standalone word anywhere in a query makes it need approval.
 */
const STATEMENT_WORDS = new Set(
	words(`
	insert update delete merge replace upsert create drop alter truncate rename
	grant revoke deny exec execute call copy load pragma set reset begin start
	commit rollback savepoint release analyze analyse vacuum attach detach lock
	unlock handler import refresh cluster reindex comment prepare deallocate
	listen unlisten notify checkpoint discard abort declare fetch move close open
	use security into do perform assert
	optimize system kill put get remove list export install uninstall undrop
	dbcc shutdown stop bulk go print raiserror throw waitfor revert disable
	enable unload msck repair cache uncache add watch exchange backup restore
	flush purge reload reconfigure setuser audit noaudit flashback associate
	disassociate administer unset change binlog xa signal resignal reassign
	truncate clear
`),
)

/** First words that make a string count as SQL (statements plus a few that never start a read). */
const SQL_START_WORDS = new Set([
	...READ_FIRST_WORDS,
	...STATEMENT_WORDS,
	...words("end check checksum from if while goto pivot unpivot summarize begin"),
])

/**
 * A lone word is usually a parameter value ("start", "set", "desc"), not a
 * statement. These few are statements on their own.
 */
const BARE_SQL_WORDS = new Set(
	words(`
	vacuum reindex cluster analyze analyse checkpoint commit rollback unlock
	reset discard begin abort end shutdown flush go
`),
)

/** Statement words that are also ordinary functions when followed by `(`. */
const FUNCTION_LIKE = new Set(
	words("replace insert truncate list get cluster"),
)
const DESTRUCTIVE_WORDS = new Set(["drop", "alter", "truncate"])

const FOR_UPDATE_RE = /\bfor\s+(?:no\s+key\s+)?update\b/giu
const LOCK_SHARE_RE = /\block\s+in\s+share\s+mode\b/giu
const FETCH_FIRST_RE = /\bfetch\s+(?:first|next)\s+(?:\d+|\?|\$\d+)\s+(?:percent\s+)?rows?\b/giu
const COMMENT_ON_RE = /(?<![\p{L}\p{N}_$.])comment\s+on(?![\p{L}\p{N}_$])/iu

const PG_READ_ONLY = new Set(
	words(`
	pg_size_pretty pg_relation_size pg_total_relation_size pg_table_size
	pg_indexes_size pg_database_size pg_typeof pg_backend_pid
	pg_postmaster_start_time pg_column_size pg_has_role pg_table_is_visible
	pg_get_userbyid pg_encoding_to_char
`),
)

const DANGER_FUNCTION_NAMES = new Set(
	words(`
	nextval setval set_config openquery openrowset opendatasource load_file
	load_extension writefile readfile edit sleep pg_sleep benchmark sys_exec
	sys_eval url file mysql postgresql get_lock release_lock release_all_locks
	curl wget hdfs gcs jdbc odbc mongodb redis sqlite executable input
	sqlite_scan postgres_scan parquet_scan glob sniff_csv deltalake iceberg
	azureblobstorage txid_current
`),
)
const DANGER_FUNCTION_PREFIXES = [
	"dblink", "lo_", "system$", "query_to_", "table_to_", "schema_to_",
	"database_to_", "cursor_to_", "xp_", "sp_", "http_", "s3", "remote", "sleep",
	"read_", "dbms_", "utl_", "file",
]

function isDangerFunction(name: string): boolean {
	const n = name.toLowerCase()
	if (n.startsWith("pg_")) {
		return !(PG_READ_ONLY.has(n) || /^pg_get_\w*def$/.test(n))
	}
	if (DANGER_FUNCTION_NAMES.has(n)) return true
	return DANGER_FUNCTION_PREFIXES.some((p) => n.startsWith(p))
}

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

const IDENT_CHAR = /[\p{L}\p{N}_$]/u
const IDENT_PLACEHOLDER = (i: number) => `\uE000${i}\uE001`

/**
 * Removes comments and quoted text in one left-to-right pass (order matters:
 * `'a--b'; DELETE ...` is a string followed by a statement). Strings become
 * `''`. Quoted identifiers become a placeholder, and their inner text goes
 * into `idents`, so a quoted function name can still be checked.
 */
function strip(sql: string, r: Reading, idents: string[]): string {
	let out = ""
	let i = 0
	const n = sql.length
	const ident = (inner: string) => {
		idents.push(inner)
		return IDENT_PLACEHOLDER(idents.length - 1)
	}
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
			if (ch === "'") {
				out += "''"
			} else {
				const inner = sql.slice(i + 1, Math.min(j, n)).split(ch + ch).join(ch)
				out += ident(inner)
			}
			i = j + 1
		} else if (ch === "[" && r.bracket) {
			const end = sql.indexOf("]", i + 1)
			out += ident(sql.slice(i + 1, end === -1 ? n : end))
			i = end === -1 ? n : end + 1
		} else if (ch === "$" && r.dollar && !(i > 0 && IDENT_CHAR.test(sql[i - 1] as string))) {
			const tag = /^\$(?:[\p{L}_][\p{L}\p{N}_]*)?\$/u.exec(sql.slice(i, i + 200))
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

/** Leading junk: whitespace, invisible and control characters, `;` and `(`. */
const LEADING_JUNK = /^[\s\p{Z}\p{Cc}\p{Cf};(]+/u

/** Strips leading junk and comments, returning the rest. */
function stripLeading(text: string): string {
	let s = text
	for (let guard = 0; guard < 10_000; guard++) {
		const trimmed = s.replace(LEADING_JUNK, "")
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

/** True when a string starts with a SQL statement keyword (and is not a lone parameter-like word). */
function looksLikeSql(text: string): boolean {
	const rest = stripLeading(text.normalize("NFKC"))
	const match = /^([\p{L}_][\p{L}\p{N}_]*)(?![\p{L}\p{N}_$])/u.exec(rest)
	if (!match) return false
	const word = (match[1] as string).toLowerCase()
	if (!SQL_START_WORDS.has(word)) return false
	if (/^[\p{L}_][\p{L}\p{N}_]*\s*;?\s*$/u.test(rest)) return BARE_SQL_WORDS.has(word)
	return true
}

type Verdict = "read" | "write" | "destructive"

const TOKEN_RE = /[\p{L}\p{N}_$]+/gu
const CALL_RE = /(\uE000\d+\uE001|[\p{L}\p{N}_$]+)\s*\(/gu

/** Judges one comment-and-literal-free reading of the SQL. */
function judge(text: string, idents: string[]): Verdict {
	let verdict: Verdict = "read"
	const bump = (v: Verdict) => {
		if (v === "destructive" || verdict === "read") verdict = v
	}
	const segments = text.split(";").filter((s) => s.trim() !== "")
	if (segments.length !== 1) bump("write")
	const first = /^[\s\p{Z}\p{Cc}\p{Cf}(]*([\p{L}_][\p{L}\p{N}_$]*)/u.exec(text)?.[1]?.toLowerCase()
	if (!first || !READ_FIRST_WORDS.has(first)) bump("write")
	const body = text
		.replace(FOR_UPDATE_RE, " ")
		.replace(LOCK_SHARE_RE, " ")
		.replace(FETCH_FIRST_RE, " ")
	// Any statement keyword as a standalone word, anywhere.
	for (const m of body.matchAll(TOKEN_RE)) {
		const index = m.index ?? 0
		const prev = index > 0 ? body[index - 1] : ""
		if (prev === "." || prev === "@") continue
		const word = m[0].toLowerCase()
		if (!STATEMENT_WORDS.has(word)) continue
		const after = body.slice(index + word.length)
		if (after.startsWith(".")) continue
		if (FUNCTION_LIKE.has(word) && /^\s*\(/.test(after)) continue
		bump(DESTRUCTIVE_WORDS.has(word) ? "destructive" : "write")
	}
	if (COMMENT_ON_RE.test(body)) bump("write")
	// Side-effect functions, by the inner text of quoted names and the last segment of qualified ones.
	for (const m of body.matchAll(CALL_RE)) {
		let name = m[1] as string
		const ph = /^\uE000(\d+)\uE001$/.exec(name)
		if (ph) name = idents[Number(ph[1])] ?? ""
		const parts = name.trim().split(".")
		if (isDangerFunction(name.trim()) || isDangerFunction((parts[parts.length - 1] ?? "").trim())) {
			bump("write")
		}
	}
	return verdict
}

/** Classifies one SQL string: read, write, or destructive (drop/alter/truncate). */
export function classifySql(sql: string): Verdict {
	try {
		if (sql.length > MAX_SQL_CHARS) return "write"
		const normalized = sql.normalize("NFKC")
		if (/\/\*M?!/.test(normalized)) return "write"
		let result: Verdict = "read"
		for (const reading of READINGS) {
			const idents: string[] = []
			const v = judge(strip(normalized, reading, idents), idents)
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
			if (looksLikeSql(value)) {
				const v = classifySql(value)
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
