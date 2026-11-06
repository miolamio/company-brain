import { describe, expect, it } from "vitest"
import { sqlContainsDdl, sqlContainsDml } from "./sql-query-check"

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
		["SELECT $$ DELETE FROM t $$"],
	])("does not flag %s", (sql) => {
		expect(flagged(sql)).toBe(false)
	})
})
