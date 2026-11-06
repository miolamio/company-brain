import { describe, expect, it } from "vitest"
import {
	isQueryTool,
	queryToolCallHasDdl,
	queryToolCallHasDml,
	sqlContainsDdl,
	sqlContainsDml,
} from "./sql-query-check"

const flagged = (sql: string) => sqlContainsDml(sql) || sqlContainsDdl(sql)

describe("SQL check bypass attempts", () => {
	it.each([
		["lowercase", "delete from t"],
		["mixed case", "DeLeTe FrOm t"],
		["leading block comment", "/* x */ DELETE FROM t"],
		["leading line comment", "-- x\nDELETE FROM t"],
		["CTE then DELETE", "WITH x AS (SELECT 1) DELETE FROM t"],
		["CTE then UPDATE", "WITH x AS (SELECT 1) UPDATE t SET a = 1"],
		["second statement", "SELECT 1; DROP TABLE t"],
		["second statement, no space", "SELECT 1;DELETE FROM t"],
		["tabs and newlines", "\t\n DELETE\r\n\tFROM t"],
		["comment between keywords", "DELETE/**/FROM t"],
		["line comment between keywords", "DELETE--x\nFROM t"],
		["-- inside a string, then a statement", "SELECT 'a--b'; DELETE FROM t"],
		["/* inside a string, then a statement", "SELECT '/*'; DELETE FROM t; SELECT '*/'"],
		["doubled quote in a string", "SELECT 'it''s'; DELETE FROM t"],
		["backslash-escaped quote (MySQL reading)", "SELECT 'a\\'; DELETE FROM t; --'"],
		["dollar-quoted string, then a statement", "SELECT $q$x$q$; DELETE FROM t"],
		["quoted table name", 'UPDATE "my table" SET a = 1'],
		["backticked table name", "UPDATE `my table` SET a = 1"],
		["UPDATE with alias", "UPDATE t AS x SET a = 1"],
		["MySQL UPDATE IGNORE", "UPDATE IGNORE t SET a = 1"],
		["INSERT without INTO", "INSERT t VALUES (1)"],
		["EXPLAIN ANALYZE of a write", "EXPLAIN ANALYZE DELETE FROM t"],
		["SELECT INTO a new table", "SELECT * INTO newt FROM t"],
		["CREATE TABLE AS", "CREATE TABLE x AS SELECT 1"],
		["COPY", "COPY t FROM '/tmp/x'"],
		["GRANT", "GRANT ALL ON t TO u"],
		["DROP of an object the old list lacked", "DROP POLICY p ON t"],
		["CALL", "CALL purge()"],
		["DO block", "SELECT 1; DO $$ BEGIN DELETE FROM t; END $$"],
		["MySQL executable comment", "SELECT 1 /*! ; DELETE FROM t */"],
		["MySQL # comment hiding a statement", "SELECT 1 # '\nDELETE FROM t # '"],
		["DELETE with multi-table JOIN", "DELETE t1 FROM t1 JOIN t2 ON t1.id = t2.id"],
		["DELETE without FROM", "DELETE t"],
		["DELETE TOP", "DELETE TOP (5) FROM t"],
		["UPDATE of two tables", "UPDATE a, b SET a.x = b.y"],
		["UPDATE bracketed name", "UPDATE [dbo].[t] SET a = 1"],
		["UPDATE TOP", "UPDATE TOP (10) t SET a = 1"],
		["REPLACE without INTO", "REPLACE t VALUES (1)"],
		["MERGE without INTO", "MERGE t USING s ON t.id = s.id WHEN MATCHED THEN DELETE"],
		["EXPLAIN ANALYZE CREATE TABLE AS", "EXPLAIN ANALYZE CREATE TABLE x AS SELECT 1"],
		["T-SQL SELECT then EXEC", "SELECT 1 EXEC sp_x"],
		["BEGIN TRAN EXEC", "BEGIN TRAN EXEC sp_x"],
		["PRAGMA assignment", "PRAGMA writable_schema = 1"],
		["SET ROLE", "SET ROLE admin"],
		["SET SESSION AUTHORIZATION", "SET SESSION AUTHORIZATION postgres"],
		["SET search_path", "SET search_path = evil"],
		["dblink_exec in SELECT", "SELECT dblink_exec('host=x', 'DELETE FROM t')"],
		["pg_terminate_backend", "SELECT pg_terminate_backend(123)"],
		["lo_import", "SELECT lo_import('/etc/passwd')"],
		["pg_write_file", "SELECT pg_write_file('/tmp/x', 'y')"],
		["set_config", "SELECT set_config('role', 'admin', false)"],
		["schema-qualified set_config", "SELECT pg_catalog.set_config('a', 'b', false)"],
		["nextval", "SELECT nextval('s')"],
		["setval", "SELECT setval('s', 1)"],
		["pg_sleep", "SELECT pg_sleep(100)"],
		["dollar quote that is only an identifier in MySQL", "SELECT $q$; DELETE FROM t; $q$"],
		["dollar tag glued to an identifier", "SELECT a$q$; DELETE FROM t; SELECT $q$"],
		["bracket identifier hiding nothing", "SELECT [a]; DELETE FROM t"],
		["SELECT INTO OUTFILE", "SELECT 1 INTO OUTFILE '/tmp/x'"],
		["ON CONFLICT DO UPDATE", "INSERT INTO t VALUES (1) ON CONFLICT DO UPDATE SET a = 1"],
	])("flags %s", (_name, sql) => {
		expect(flagged(sql)).toBe(true)
	})

	it.each([
		["SELECT * FROM t WHERE a = 'x--y' AND b = 2"],
		["SELECT 'DELETE FROM t'"],
		["SELECT * FROM t FOR UPDATE"],
		["SELECT \"update\", \"drop\" FROM t"],
		["SELECT created_at FROM t ORDER BY created_at DESC"],
		["WITH x AS (SELECT 1) SELECT * FROM x"],
		["SELECT 1"],
		["SELECT * FROM t;"],
		["SHOW TABLES"],
		["DESCRIBE users"],
		["DESC users"],
		["EXPLAIN SELECT * FROM t"],
		["VALUES (1), (2)"],
		["TABLE users"],
		["SELECT updated_at, deleted_at FROM t"],
		["SELECT 'drop table x', 'delete from y' FROM t"],
		["SELECT replace(name, 'a', 'b') FROM t"],
		["SELECT t.drop, t.update FROM t"],
		["SELECT * FROM t -- DELETE FROM t"],
		["SELECT a # b FROM t"],
		["SELECT * FROM t FOR NO KEY UPDATE"],
	])("does not flag %s", (sql) => {
		expect(flagged(sql)).toBe(false)
	})
})

describe("whole-call classification", () => {
	const sqlTool = "run_query"

	it("looks inside JSON-encoded strings", () => {
		expect(queryToolCallHasDml(sqlTool, { payload: '{"sql":"DELETE FROM t"}' })).toBe(true)
		expect(queryToolCallHasDml(sqlTool, { payload: JSON.stringify({ a: [JSON.stringify({ q: "DELETE FROM t" })] }) })).toBe(true)
		expect(queryToolCallHasDdl(sqlTool, { payload: '[{"sql":"DROP TABLE t"}]' })).toBe(true)
		expect(queryToolCallHasDml(sqlTool, { payload: '{"sql":"SELECT 1"}' })).toBe(false)
	})

	it("does not flag prose or parameter values", () => {
		for (const text of [
			"look into the outage",
			"how to drop table in postgres",
			"update the config to set X",
			"please insert into the doc",
			"start",
			"set",
			"2024-01-01",
		]) {
			expect(queryToolCallHasDml(sqlTool, { query: text })).toBe(false)
			expect(queryToolCallHasDdl(sqlTool, { query: text })).toBe(false)
		}
	})

	it("still catches statements whose grammar is split by comments", () => {
		for (const sql of ["UPDATE/**/t/**/SET a=1", "DELETE/**/FROM t", "DROP/**/TABLE t", "insert/**/into t values (1)"]) {
			expect(
				queryToolCallHasDml(sqlTool, { sql }) || queryToolCallHasDdl(sqlTool, { sql }),
			).toBe(true)
		}
	})

	it("fails closed on a huge argument instead of throwing", () => {
		const huge = Array.from({ length: 300_000 }, () => "a")
		expect(queryToolCallHasDml(sqlTool, { huge })).toBe(true)
		expect(queryToolCallHasDml(sqlTool, { sql: `SELECT ${"x,".repeat(60_000)}1` })).toBe(true)
	})

	it("fails closed on a getter that throws", () => {
		const bad = {
			get sql(): string {
				throw new Error("boom")
			},
		}
		expect(queryToolCallHasDml(sqlTool, bad)).toBe(true)
	})

	it("recognises the wider set of query tool names", () => {
		for (const name of ["execute_statement", "db_exec", "run_sql", "execute", "db_query"]) {
			expect(isQueryTool(name)).toBe(true)
		}
		for (const name of ["search_issues", "get_user", "list_tables", "create_issue"]) {
			expect(isQueryTool(name)).toBe(false)
		}
	})
})
