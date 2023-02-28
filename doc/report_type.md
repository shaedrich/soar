# Supported Report Types

[toc]

## lint
* **Description**:Reference sqlint format, integrated into the code editor as a plugin, displaying output more friendly

* **Example**:

```bash
soar -report-type lint -query test.sql
```
## markdown
* **Description**:This format is the default output format, presented in markdown format, which can be opened directly with the web browser plugin, or with a markdown editor

* **Example**:

```bash
echo "select * from film" | soar
```
## rewrite
* **Description**:SQL rewrite function, use with -rewrite-rules parameter, you can see all supported SQL rewrite rules with -list-rewrite-rules

* **Example**:

```bash
echo "select * from film" | soar -rewrite-rules star2columns,delimiter -report-type rewrite
```
## ast
* **Description**:Outputs an abstract syntax tree of SQL, mainly for testing

* **Example**:

```bash
echo "select * from film" | soar -report-type ast
```
## ast-json
* **Description**:Outputs an abstract syntax tree of SQL in JSON format, mainly for testing

* **Example**:

```bash
echo "select * from film" | soar -report-type ast-json
```
## tiast
* **Description**:Outputs the TiDB abstract syntax tree for SQL, mainly for testing

* **Example**:

```bash
echo "select * from film" | soar -report-type tiast
```
## tiast-json
* **Description**:TiDB abstract syntax tree for exporting SQL in JSON format, mainly for testing

* **Example**:

```bash
echo "select * from film" | soar -report-type tiast-json
```
## tables
* **Description**:Export the name of the library table used by SQL in JSON format

* **Example**:

```bash
echo "select * from film" | soar -report-type tables
```
## query-type
* **Description**:The request type of the SQL statement

* **Example**:

```bash
echo "select * from film" | soar -report-type query-type
```
## fingerprint
* **Description**:Output fingerprint of SQL

* **Example**:

```bash
echo "select * from film where language_id=1" | soar -report-type fingerprint
```
## md2html
* **Description**:markdown format to html format widget

* **Example**:

```bash
soar -list-heuristic-rules | soar -report-type md2html > heuristic_rules.html
```
## explain-digest
* **Description**:Enter a table in EXPLAIN, JSON or Vertical format, analyze it, and give the results

* **Example**:

```bash
soar -report-type explain-digest << EOF
+----+-------------+-------+------+---------------+------+---------+------+------+-------+
| id | select_type | table | type | possible_keys | key | key_len | ref | rows | Extra |
+----+-------------+-------+------+---------------+------+---------+------+------+-------+
| 1 | SIMPLE | film | ALL | NULL | NULL | NULL | NULL | 1131 | |
+----+-------------+-------+------+---------------+------+---------+------+------+-------+
EOF
```
## duplicate-key-checker
* **Description**:Index duplicate checker for the specified database in OnlineDsn

* **Example**:

```bash
soar -report-type duplicate-key-checker -online-dsn user:password@127.0.0.1:3306/db
```
## html
* **Description**:Export reports in HTML format

* **Example**:

```bash
echo "select * from film" | soar -report-type html
```
## json
* **Description**:Output JSON format report, easy for application to handle

* **Example**:

```bash
echo "select * from film" | soar -report-type json
```
## tokenize
* **Description**:cut words to SQL, mainly for testing

* **Example**:

```bash
echo "select * from film" | soar -report-type tokenize
```
## compress
* **Description**:SQL compression widget, using built-in SQL compression logic, feature under test

* **Example**:

```bash
echo "select
*
from
  film" | soar -report-type compress
```
## pretty
* **Description**:Use kr/pretty to print reports, mainly for testing

* **Example**:

```bash
echo "select * from film" | soar -report-type pretty
```
## remove-comment
* **Description**:Remove comments from SQL statements, supports single line and multi-line comment removal

* **Example**:

```bash
echo "select/*comment*/ * from film" | soar -report-type remove-comment
```
## chardet
* **Description**:Guess the character set used by the input SQL

* **Example**:

```bash
echo 'Chinese' | soar -report-type chardet
```
