/*
 * Copyright 2018 Xiaomi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package advisor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/yassineim/soar/ast"
	"github.com/yassineim/soar/common"

	"github.com/kr/pretty"
	"github.com/percona/go-mysql/query"
	tidb "github.com/pingcap/parser/ast"
	"vitess.io/vitess/go/vt/sqlparser"
)

// Query4Audit 待评审的SQL结构体，由原SQL和其对应的抽象语法树组成
type Query4Audit struct {
	Query  string              // 查询语句
	Stmt   sqlparser.Statement // 通过Vitess解析出的抽象语法树
	TiStmt []tidb.StmtNode     // 通过TiDB解析出的抽象语法树
}

// NewQuery4Audit return a struct for Query4Audit
func NewQuery4Audit(sql string, options ...string) (*Query4Audit, error) {
	var err, vErr error
	var charset string
	var collation string

	if len(options) > 0 {
		charset = options[0]
	}

	if len(options) > 1 {
		collation = options[1]
	}

	q := &Query4Audit{Query: sql}
	// vitess 语法解析不上报，以 tidb parser 为主
	q.Stmt, vErr = sqlparser.Parse(sql)
	if vErr != nil {
		common.Log.Warn("NewQuery4Audit vitess parse Error: %s, Query: %s", vErr.Error(), sql)
	}

	// TODO: charset, collation
	// tidb parser 语法解析
	q.TiStmt, err = ast.TiParse(sql, charset, collation)
	return q, err
}

// Rule 评审规则元数据结构
type Rule struct {
	Item     string                  `json:"Item"`     // 规则代号
	Severity string                  `json:"Severity"` // 危险等级：L[0-8], 数字越大表示级别越高
	Summary  string                  `json:"Summary"`  // 规则摘要
	Content  string                  `json:"Content"`  // 规则解释
	Case     string                  `json:"Case"`     // SQL示例
	Position int                     `json:"Position"` // 建议所处SQL字符位置，默认0表示全局建议
	Func     func(*Query4Audit) Rule `json:"-"`        // 函数名
}

/*

## Item单词缩写含义

* ALI   Alias(AS)
* ALT   Alter
* ARG   Argument
* CLA   Classic
* COL   Column
* DIS   Distinct
* ERR   Error, 特指MySQL执行返回的报错信息, ERR.000为vitess语法错误，ERR.001为执行错误，ERR.002为EXPLAIN错误
* EXP   Explain, 由explain模块给
* FUN   Function
* IDX   Index, 由index模块给
* JOI   Join
* KEY   Key
* KWR   Keyword
* LCK	Lock
* LIT   Literal
* PRO   Profiling, 由profiling模块给
* RES   Result
* SEC   Security
* STA   Standard
* SUB   Subquery
* TBL   TableName
* TRA   Trace, 由trace模块给

*/

// HeuristicRules 启发式规则列表
var HeuristicRules map[string]Rule

func init() {
	InitHeuristicRules()
}

// InitHeuristicRules ...
func InitHeuristicRules() {
	HeuristicRules = map[string]Rule{
		"OK": {
			Item:     "OK",
			Severity: "L0",
			Summary:  "OK",
			Content:  `OK`,
			Case:     "OK",
			Func:     (*Query4Audit).RuleOK,
		},
		"ALI.001": {
			Item:     "ALI.001",
			Severity: "L0",
			Summary:  "It is recommended to declare an alias using the AS keyword display",
			Content:  `In column or table aliases (e.g., "tbl AS alias"), explicit use of the AS keyword is easier to understand than implicit aliases (e.g., "tbl alias").`,
			Case:     "select name from tbl t1 where id < 1000",
			Func:     (*Query4Audit).RuleImplicitAlias,
		},
		"ALI.002": {
			Item:     "ALI.002",
			Severity: "L8",
			Summary:  "It is not recommended to set aliases for the column wildcard '*'",
			Content:  `Example: "SELECT tbl.* col1, col2" The above SQL sets alias for column wildcard, there may be a logical error in such SQL. You may mean to query col1, but instead of it, the renamed column is the last column of tbl.`,
			Case:     "select tbl.* as c1,c2,c3 from tbl where id < 1000",
			Func:     (*Query4Audit).RuleStarAlias,
		},
		"ALI.003": {
			Item:     "ALI.003",
			Severity: "L1",
			Summary:  "Alias should not be the same as the name of a table or column",
			Content:  `The alias of a table or column is the same as its real name, which makes it more difficult to distinguish between queries.`,
			Case:     "select name from tbl as tbl where id < 1000",
			Func:     (*Query4Audit).RuleSameAlias,
		},
		"ALT.001": {
			Item:     "ALT.001",
			Severity: "L4",
			Summary:  "Changing the default character set of a table does not change the character set of each field of the table",
			Content:  `Many beginners mistake ALTER TABLE tbl_name [DEFAULT] CHARACTER SET 'UTF8' for changing the character set of all fields, but in fact it only affects the new fields added later and does not change the character set of the existing fields in the table. If you want to change the character set of all fields in the whole table, you should use ALTER TABLE tbl_name CONVERT TO CHARACTER SET charset_name;`,
			Case:     "ALTER TABLE tbl_name CONVERT TO CHARACTER SET charset_name;",
			Func:     (*Query4Audit).RuleAlterCharset,
		},
		"ALT.002": {
			Item:     "ALT.002",
			Severity: "L2",
			Summary:  "Multiple ALTER requests for the same table are recommended to be combined into one",
			Content:  `Every table structure change has an impact on the online service, so please try to reduce the number of operations by merging ALTER requests even if you can make adjustments through online tools.`,
			Case:     "ALTER TABLE tbl ADD COLUMN col int, ADD INDEX idx_col (`col`);",
			Func:     (*Query4Audit).RuleOK, // 该建议在indexAdvisor中给
		},
		"ALT.003": {
			Item:     "ALT.003",
			Severity: "L0",
			Summary:  "Delete as a high-risk operation, please pay attention to check whether the business logic has any dependencies before operation",
			Content:  `If the business logic dependency is not completely eliminated, the deletion of a column may lead to a situation where data cannot be written or the deleted column data cannot be queried resulting in program exceptions. In this case, even if the data is rolled back by backup, the data requested by the user to be written will be lost.`,
			Case:     "ALTER TABLE tbl DROP COLUMN col;",
			Func:     (*Query4Audit).RuleAlterDropColumn,
		},
		"ALT.004": {
			Item:     "ALT.004",
			Severity: "L0",
			Summary:  "Deleting primary keys and foreign keys is a high-risk operation, please check with DBA before operation.",
			Content:  `The primary key and foreign key are two important constraints in the relational database, deleting existing constraints will break the existing business logic, so please confirm the impact with the DBA before operation and think twice.`,
			Case:     "ALTER TABLE tbl DROP PRIMARY KEY;",
			Func:     (*Query4Audit).RuleAlterDropKey,
		},
		"ARG.001": {
			Item:     "ARG.001",
			Severity: "L4",
			Summary:  "It is not recommended to use the antecedent wildcard lookup",
			Content:  `For example, "%foo", the query parameter with a leading wildcard cannot use existing indexes.`,
			Case:     "select c1,c2,c3 from tbl where name like '%foo'",
			Func:     (*Query4Audit).RulePrefixLike,
		},
		"ARG.002": {
			Item:     "ARG.002",
			Severity: "L1",
			Summary:  "LIKE queries without wildcards",
			Content:  `A LIKE query that does not contain a wildcard may have a logical error because it is logically the same as an equals query.`,
			Case:     "select c1,c2,c3 from tbl where name like 'foo'",
			Func:     (*Query4Audit).RuleEqualLike,
		},
		"ARG.003": {
			Item:     "ARG.003",
			Severity: "L4",
			Summary:  "Parameter comparison contains implicit conversions and cannot use indexes",
			Content:  "Implicit type conversions run the risk of not hitting the index, and the consequences of not hitting the index are very serious in the case of high concurrency and large data volume.",
			Case:     "SELECT * FROM sakila.film WHERE length >= '60';",
			Func:     (*Query4Audit).RuleOK, // 该建议在IndexAdvisor中给，RuleImplicitConversion
		},
		"ARG.004": {
			Item:     "ARG.004",
			Severity: "L4",
			Summary:  "IN (NULL)/NOT IN (NULL) Always not true",
			Content:  "The correct way is col IN ('val1', 'val2', 'val3') OR col IS NULL",
			Case:     "SELECT * FROM tb WHERE col IN (NULL);",
			Func:     (*Query4Audit).RuleIn,
		},
		"ARG.005": {
			Item:     "ARG.005",
			Severity: "L1",
			Summary:  "IN should be used with caution, too many elements will lead to a full table scan",
			Content:  ` For example: select id from t where num in(1,2,3) For continuous values, use BETWEEN instead of IN: select id from t where num between 1 and 3. And when there are too many IN values MySQL may also enter a full table scan resulting in a sharp performance drop.`,
			Case:     "select id from t where num in(1,2,3)",
			Func:     (*Query4Audit).RuleIn,
		},
		"ARG.006": {
			Item:     "ARG.006",
			Severity: "L1",
			Summary:  "NULL value determination of fields in WHERE clause should be avoided as much as possible",
			Content:  `Using IS NULL or IS NOT NULL will probably cause the engine to drop the index and do a full table scan, e.g. select id from t where num is null; you can set the default value of 0 on num to ensure that the num column in the table does not have a NULL value, and then query it like this: select id from t where num=0;`,
			Case:     "select id from t where num is null",
			Func:     (*Query4Audit).RuleIsNullIsNotNull,
		},
		"ARG.007": {
			Item:     "ARG.007",
			Severity: "L3",
			Summary:  "Avoid using pattern matching",
			Content:  `Performance issues are the biggest drawback of using the pattern matching operator. Another problem with pattern matching queries using LIKE or regular expressions is that they may return unexpected results. The best solution is to use a special search engine technology instead of SQL, such as Apache Lucene, and another option is to save the results to reduce the overhead of repeated searches. If you must use SQL, consider using a third-party extension like FULLTEXT indexing in MySQL. But more generally, you don't have to use SQL to solve all your problems.`,
			Case:     "select c_id,c2,c3 from tbl where c2 like 'test%'",
			Func:     (*Query4Audit).RulePatternMatchingUsage,
		},
		"ARG.008": {
			Item:     "ARG.008",
			Severity: "L1",
			Summary:  "OR Please use IN predicate as much as possible when querying index columns",
			Content:  `IN-list predicates can be used for index retrieval, and the optimizer can sort the IN-list to match the sorted sequence of the index for a more efficient retrieval. Note that the IN-list must contain only constants, or hold the value of a constant, such as an outer reference, for the duration of the query block execution.`,
			Case:     "SELECT c1,c2,c3 FROM tbl WHERE c1 = 14 OR c1 = 17",
			Func:     (*Query4Audit).RuleORUsage,
		},
		"ARG.009": {
			Item:     "ARG.009",
			Severity: "L1",
			Summary:  "A string in quotation marks contains spaces at the beginning or end of the string",
			Content:  `If there are spaces before and after the VARCHAR column this may cause logical problems, e.g. in MySQL 5.5 'a' and 'a ' may be considered the same value in the query.`,
			Case:     "SELECT 'abc '",
			Func:     (*Query4Audit).RuleSpaceWithQuote,
		},
		"ARG.010": {
			Item:     "ARG.010",
			Severity: "L1",
			Summary:  "Do not use hint, such as: sql_no_cache, force index, ignore key, straight join, etc.",
			Content:  `hint is used to force SQL to execute according to a certain execution plan, but as the amount of data changes we cannot guarantee that our initial prediction is correct.`,
			Case:     "SELECT * FROM t1 USE INDEX (i1) ORDER BY a;",
			Func:     (*Query4Audit).RuleHint,
		},
		"ARG.011": {
			Item:     "ARG.011",
			Severity: "L3",
			Summary:  "Do not use negative queries, e.g. NOT IN/NOT LIKE",
			Content:  `Please try not to use negative queries, which will result in full table scans and have a large impact on query performance.`,
			Case:     "select id from t where num not in(1,2,3);",
			Func:     (*Query4Audit).RuleNot,
		},
		"ARG.012": {
			Item:     "ARG.012",
			Severity: "L2",
			Summary:  "Too much data for one INSERT/REPLACE",
			Content:  "A single INSERT/REPLACE statement inserting a large amount of data in a batch has poor performance and may even cause a delay in synchronization from the library. In order to improve performance and reduce the impact of batch write data on slave synchronization delay, it is recommended to use batch insert method.",
			Case:     "INSERT INTO tb (a) VALUES (1), (2)",
			Func:     (*Query4Audit).RuleInsertValues,
		},
		"ARG.013": {
			Item:     "ARG.013",
			Severity: "L0",
			Summary:  "DDL statements use Chinese full angle quotes",
			Content:  "The DDL statement uses Chinese full-angle quotation marks \"\" or '', this may be a writing error, please check if it is as expected.",
			Case:     "CREATE TABLE tb (a varchar(10) default '“”'",
			Func:     (*Query4Audit).RuleFullWidthQuote,
		},
		"ARG.014": {
			Item:     "ARG.014",
			Severity: "L4",
			Summary:  "The presence of a column name in the IN condition may cause the data to be matched in a wider range",
			Content:  `For example, delete from t where id in(1, 2, id) may cause the full table data to be deleted by mistake. Please double check the correctness of the IN condition.`,
			Case:     "select id from t where id in(1, 2, id)",
			Func:     (*Query4Audit).RuleIn,
		},
		"CLA.001": {
			Item:     "CLA.001",
			Severity: "L4",
			Summary:  "Outermost SELECT Unspecified WHERE condition",
			Content:  `The SELECT statement does not have a WHERE clause and may check more rows than expected (full table scan). For SELECT COUNT(*) type requests that do not require precision, it is recommended to use SHOW TABLE STATUS or EXPLAIN instead.`,
			Case:     "select id from tbl",
			Func:     (*Query4Audit).RuleNoWhere,
		},
		"CLA.002": {
			Item:     "CLA.002",
			Severity: "L3",
			Summary:  "ORDER BY RAND() is not recommended",
			Content:  `ORDER BY RAND() is a very inefficient way to retrieve random rows from the result set, because it sorts the entire result and discards most of its data.`,
			Case:     "select name from tbl where id < 1000 order by rand(number)",
			Func:     (*Query4Audit).RuleOrderByRand,
		},
		"CLA.003": {
			Item:     "CLA.003",
			Severity: "L2",
			Summary:  "LIMIT queries with OFFSET are not recommended",
			Content:  `Paging the result set using LIMIT and OFFSET is O(n^2) complex and causes performance problems as the data grows. Paging is more efficient using the "bookmark" scan method.`,
			Case:     "select c1,c2 from tbl where name=xx order by number limit 1 offset 20",
			Func:     (*Query4Audit).RuleOffsetLimit,
		},
		"CLA.004": {
			Item:     "CLA.004",
			Severity: "L2",
			Summary:  "GROUP BY is not recommended for constants",
			Content:  `GROUP BY 1 means GROUP BY by the first column. if you use numbers in the GROUP BY clause instead of expressions or column names, it may cause problems when the query column order changes.`,
			Case:     "select col1,col2 from tbl group by 1",
			Func:     (*Query4Audit).RuleGroupByConst,
		},
		"CLA.005": {
			Item:     "CLA.005",
			Severity: "L2",
			Summary:  "ORDER BY constant column doesn't make any sense",
			Content:  `There may be errors in the SQL logic; at best, it is a useless operation that does not change the query result.`,
			Case:     "select id from test where id=1 order by id",
			Func:     (*Query4Audit).RuleOrderByConst,
		},
		"CLA.006": {
			Item:     "CLA.006",
			Severity: "L4",
			Summary:  "GROUP BY or ORDER BY in different tables",
			Content:  `This will force the use of temporary tables and filesort, which can create significant performance hazards and can consume a lot of memory and temporary space on disk.`,
			Case:     "select tb1.col, tb2.col from tb1, tb2 where id=1 group by tb1.col, tb2.col",
			Func:     (*Query4Audit).RuleDiffGroupByOrderBy,
		},
		"CLA.008": {
			Item:     "CLA.008",
			Severity: "L2",
			Summary:  "Please add an ORDER BY condition to the GROUP BY display",
			Content:  `By default MySQL will sort 'GROUP BY col1, col2, ...' requests in the following order 'ORDER BY col1, col2, ...' . If the GROUP BY statement does not specify the ORDER BY condition, it will result in unnecessary sorting, so it is recommended to add 'ORDER BY NULL' if sorting is not required.`,
			Case:     "select c1,c2,c3 from t1 where c1='foo' group by c2",
			Func:     (*Query4Audit).RuleExplicitOrderBy,
		},
		"CLA.009": {
			Item:     "CLA.009",
			Severity: "L2",
			Summary:  "The ORDER BY condition is an expression",
			Content:  `Temporary tables are used when the ORDER BY condition is an expression or function, and performance is poor when WHERE is not specified or when the WHERE condition returns a large result set.`,
			Case:     "select description from film where title ='ACADEMY DINOSAUR' order by length-language_id;",
			Func:     (*Query4Audit).RuleOrderByExpr,
		},
		"CLA.010": {
			Item:     "CLA.010",
			Severity: "L2",
			Summary:  "The conditions of GROUP BY are expressions",
			Content:  `Temporary tables are used when the GROUP BY condition is an expression or function, which can cause poor performance when WHERE is not specified or when the WHERE condition returns a large result set.`,
			Case:     "select description from film where title ='ACADEMY DINOSAUR' GROUP BY length-language_id;",
			Func:     (*Query4Audit).RuleGroupByExpr,
		},
		"CLA.011": {
			Item:     "CLA.011",
			Severity: "L1",
			Summary:  "Suggest adding comments to the table",
			Content:  `Adding comments to a table can make the meaning of the table clearer, thus making it much easier to maintain in the future.`,
			Case:     "CREATE TABLE `test1` (`ID` bigint(20) NOT NULL AUTO_INCREMENT,`c1` varchar(128) DEFAULT NULL,PRIMARY KEY (`ID`)) ENGINE=InnoDB DEFAULT CHARSET=utf8",
			Func:     (*Query4Audit).RuleTblCommentCheck,
		},
		"CLA.012": {
			Item:     "CLA.012",
			Severity: "L2",
			Summary:  "Decompose complex wrap-around queries into a few simple queries",
			Content:  `SQL is a very expressive language and you can do a lot of things in a single SQL query or in a single statement. But that doesn't mean that you have to force only one line of code, or that it's a good idea to use one line of code to take care of every task. A common consequence of passing a query to get all the results is that you get a Cartesian product. This happens when there are no conditions between the two tables in the query that restrict their relationship. A direct join query using two tables without corresponding restrictions yields one combination of each row in the first table and each row in the second table. Each such combination becomes a row in the result set, and you end up with a result set with a large number of rows. It is important to consider that these queries are difficult to write, difficult to modify and difficult to debug. The increasing number of database query requests should be expected. Managers want more complex reports and more fields added to the user interface. If your design is complex and a single query, it can be time consuming to extend them. The time spent on these things is not worth it for either you or the project. Break up complex spaghetti-style queries into a few simple ones. When you break up a complex SQL query, the result can be many similar queries that may differ only in data type. Writing all of these queries can be tedious, so it's a good idea to have a program that generates this code automatically. SQL code generation is a great application for this. Although SQL supports solving complex problems with a single line of code, don't do anything impractical.`,
			Case:     "This is a long, long SQL, and the case is omitted.",
			Func:     (*Query4Audit).RuleSpaghettiQueryAlert,
		},

		/*
			https://www.datacamp.com/community/tutorials/sql-tutorial-query
			The HAVING Clause
			The HAVING clause was originally added to SQL because the WHERE keyword could not be used with aggregate functions. HAVING is typically used with the GROUP BY clause to restrict the groups of returned rows to only those that meet certain conditions. However, if you use this clause in your query, the index is not used, which -as you already know- can result in a query that doesn't really perform all that well.

			If you’re looking for an alternative, consider using the WHERE clause. Consider the following queries:

			SELECT state, COUNT(*)
			  FROM Drivers
			 WHERE state IN ('GA', 'TX')
			 GROUP BY state
			 ORDER BY state
			SELECT state, COUNT(*)
			  FROM Drivers
			 GROUP BY state
			HAVING state IN ('GA', 'TX')
			 ORDER BY state
			The first query uses the WHERE clause to restrict the number of rows that need to be summed, whereas the second query sums up all the rows in the table and then uses HAVING to throw away the sums it calculated. In these types of cases, the alternative with the WHERE clause is obviously the better one, as you don’t waste any resources.

			You see that this is not about limiting the result set, rather about limiting the intermediate number of records within a query.

			Note that the difference between these two clauses lies in the fact that the WHERE clause introduces a condition on individual rows, while the HAVING clause introduces a condition on aggregations or results of a selection where a single result, such as MIN, MAX, SUM,… has been produced from multiple rows.
		*/
		"CLA.013": {
			Item:     "CLA.013",
			Severity: "L3",
			Summary:  "The HAVING clause is not recommended",
			Content:  `Rewriting the HAVING clause of a query as a query condition in WHERE allows the index to be used during query processing.`,
			Case:     "SELECT s.c_id,count(s.c_id) FROM s where c = test GROUP BY s.c_id HAVING s.c_id <> '1660' AND s.c_id <> '2' order by s.c_id",
			Func:     (*Query4Audit).RuleHavingClause,
		},
		"CLA.014": {
			Item:     "CLA.014",
			Severity: "L2",
			Summary:  "It is recommended to use TRUNCATE instead of DELETE when deleting a full table",
			Content:  `It is recommended to use TRUNCATE instead of DELETE when deleting a full table`,
			Case:     "delete from tbl",
			Func:     (*Query4Audit).RuleNoWhere,
		},
		"CLA.015": {
			Item:     "CLA.015",
			Severity: "L4",
			Summary:  "UPDATE does not specify WHERE condition",
			Content:  `UPDATE without WHERE condition is generally fatal, please think twice before you do it`,
			Case:     "update tbl set col=1",
			Func:     (*Query4Audit).RuleNoWhere,
		},
		"CLA.016": {
			Item:     "CLA.016",
			Severity: "L2",
			Summary:  "Do not UPDATE the primary key",
			Content:  `The primary key is the unique identifier of the records in the data table, and it is not recommended to update the primary key column frequently, which will affect the metadata statistics and thus the normal query.`,
			Case:     "update tbl set col=1",
			Func:     (*Query4Audit).RuleOK, // 该建议在indexAdvisor中给 RuleUpdatePrimaryKey
		},
		"COL.001": {
			Item:     "COL.001",
			Severity: "L1",
			Summary:  "SELECT * type queries are not recommended",
			Content:  `When the table structure is changed, selecting all columns using the * wildcard character will cause the meaning and behavior of the query to change, possibly causing the query to return more data.`,
			Case:     "select * from tbl where id=1",
			Func:     (*Query4Audit).RuleSelectStar,
		},
		"COL.002": {
			Item:     "COL.002",
			Severity: "L2",
			Summary:  "INSERT/REPLACE Unspecified column name",
			Content:  `When the table structure is changed, if the INSERT or REPLACE request does not explicitly specify the column names, the result of the request will be different from what is expected; it is recommended to use "INSERT INTO tbl(col1, col2) VALUES ..." instead.`,
			Case:     "insert into tbl values(1,'name')",
			Func:     (*Query4Audit).RuleInsertColDef,
		},
		"COL.003": {
			Item:     "COL.003",
			Severity: "L2",
			Summary:  "It is recommended to change the self-incrementing ID to unsigned type",
			Content:  `It is recommended to change the self-incrementing ID to unsigned type`,
			Case:     "create table test(`id` int(11) NOT NULL AUTO_INCREMENT)",
			Func:     (*Query4Audit).RuleAutoIncUnsigned,
		},
		"COL.004": {
			Item:     "COL.004",
			Severity: "L1",
			Summary:  "Please add default values for columns",
			Content:  `Please add default values for the columns and don't forget to write the default values of the original fields if it is an ALTER operation. There is no default value for the field, and you cannot change the table structure online when the table is larger.`,
			Case:     "CREATE TABLE tbl (col int) ENGINE=InnoDB;",
			Func:     (*Query4Audit).RuleAddDefaultValue,
		},
		"COL.005": {
			Item:     "COL.005",
			Severity: "L1",
			Summary:  "Column not annotated",
			Content:  `It is recommended to add comments to each column in the table to clarify the meaning and role of each column in the table.`,
			Case:     "CREATE TABLE tbl (col int) ENGINE=InnoDB;",
			Func:     (*Query4Audit).RuleColCommentCheck,
		},
		"COL.006": {
			Item:     "COL.006",
			Severity: "L3",
			Summary:  "It is recommended to add comments to each column in the table to clarify the meaning and role of each column in the table.",
			Content:  `It is recommended to add comments to each column in the table to clarify the meaning and role of each column in the table.`,
			Case:     "CREATE TABLE tbl ( cols ....);",
			Func:     (*Query4Audit).RuleTooManyFields,
		},
		"COL.007": {
			Item:     "COL.007",
			Severity: "L3",
			Summary:  "Table contains too many text/blob columns",
			Content:  fmt.Sprintf(`Table containing more than %d text/blob columns`, common.Config.MaxTextColsCount),
			Case:     "CREATE TABLE tbl ( cols ....);",
			Func:     (*Query4Audit).RuleTooManyFields,
		},
		"COL.008": {
			Item:     "COL.008",
			Severity: "L1",
			Summary:  "VARCHAR can be used instead of CHAR, VARBINARY instead of BINARY",
			Content:  `for firstly variable-length fields have small storage space and can save storage space. Secondly, for queries, it is obviously more efficient to search within a relatively small field.`,
			Case:     "create table t1(id int,name char(20),last_time date)",
			Func:     (*Query4Audit).RuleVarcharVSChar,
		},
		"COL.009": {
			Item:     "COL.009",
			Severity: "L2",
			Summary:  "Exact data types are recommended",
			Content:  `In fact, any design that uses the FLOAT, REAL or DOUBLE PRECISION data types is likely to be anti-pattern. Most applications use floating point numbers that do not need to take values in the maximum/minimum intervals defined by the IEEE 754 standard. The impact of non-exact floating point numbers accumulated when calculating totals is severe. Use the NUMERIC or DECIMAL types in SQL for fixed precision decimal storage instead of FLOAT and similar data types. These data types store data exactly according to the precision you specified when you defined the column. Whenever possible, do not use floating point numbers.`,
			Case:     "CREATE TABLE tab2 (p_id  BIGINT UNSIGNED NOT NULL,a_id  BIGINT UNSIGNED NOT NULL,hours float not null,PRIMARY KEY (p_id, a_id))",
			Func:     (*Query4Audit).RuleImpreciseDataType,
		},
		"COL.010": {
			Item:     "COL.010",
			Severity: "L2",
			Summary:  "ENUM/BIT/SET data types are not recommended",
			Content:  `ENUM defines the type of the values in the column. When using strings to represent the values in ENUM, the data actually stored in the column is the ordinal number of those values at the time of definition. Therefore, the data in this column is byte-aligned, and when you perform a sort query, the results are sorted by the actual stored ordinal values, not by the alphabetical order of the string values. This may not be what you want. There is no syntax for adding or removing a value from an ENUM or check constraint; you can only redefine the column using a new set. If you intend to deprecate an option, you may struggle with the historical data. As a strategy, changing metadata-that is, changing table and column definitions-should be uncommon, with attention to testing and quality assurance. There is a better solution to constrain the optional values in a column: create a checklist with each row containing a candidate value allowed in the column; then declare a foreign key constraint on the old table that references the new table.`,
			Case:     "create table tab1(status ENUM('new','in progress','fixed'))",
			Func:     (*Query4Audit).RuleValuesInDefinition,
		},
		// 这个建议从sqlcheck迁移来的，实际生产环境每条建表SQL都会给这条建议，看多了会不开心。
		"COL.011": {
			Item:     "COL.011",
			Severity: "L0",
			Summary:  "NULL is used when a unique constraint is required, and NOT NULL is used only when the column cannot have a missing value",
			Content:  `NULL is not the same as 0. 10 times NULL is still NULL. NULL is not the same as an empty string. Combining a string with NULL in standard SQL still results in NULL. nULL and FALSE are also different. and the three boolean operations AND, OR, and NOT also confuse many people when they involve NULL. When you declare a column as NOT NULL, that means that every value in the column must exist and be meaningful. Use NULL to indicate a null value of any type that does not exist. When you declare a column as NOT NULL, it means that every value in the column must exist and be meaningful.`,
			Case:     "select c1,c2,c3 from tbl where c4 is null or c4 <> 1",
			Func:     (*Query4Audit).RuleNullUsage,
		},
		"COL.012": {
			Item:     "COL.012",
			Severity: "L5",
			Summary:  "Fields of type TEXT, BLOB and JSON are not recommended to be set to NOT NULL",
			Content:  `TEXT, BLOB, and JSON type fields cannot be specified with a non-NULL default value, and writing data without specifying a value for the field may result in a write failure if the NOT NULL restriction is added.`,
			Case:     "CREATE TABLE `tb`(`c` longblob NOT NULL);",
			Func:     (*Query4Audit).RuleBLOBNotNull,
		},
		"COL.013": {
			Item:     "COL.013",
			Severity: "L4",
			Summary:  "TIMESTAMP type default value check exception",
			Content:  `The TIMESTAMP type is recommended to set the default value and it is not recommended to use 0 or 0000-00-00 00:00:00 as the default value. Consider using 1970-08-02 01:01:01`,
			Case:     "CREATE TABLE tbl( `id` bigint not null, `create_time` timestamp);",
			Func:     (*Query4Audit).RuleTimestampDefault,
		},
		"COL.014": {
			Item:     "COL.014",
			Severity: "L5",
			Summary:  "Specifies the character set for the column",
			Content:  `It is recommended to use the same character set for columns and tables, and not to specify the character set for columns separately.`,
			Case:     "CREATE TABLE `tb2` ( `id` int(11) DEFAULT NULL, `col` char(10) CHARACTER SET utf8 DEFAULT NULL)",
			Func:     (*Query4Audit).RuleColumnWithCharset,
		},
		// https://stackoverflow.com/questions/3466872/why-cant-a-text-column-have-a-default-value-in-mysql
		"COL.015": {
			Item:     "COL.015",
			Severity: "L4",
			Summary:  "Fields of type TEXT, BLOB and JSON cannot be assigned non-NULL default values",
			Content:  `MySQL database fields of type TEXT, BLOB and JSON cannot specify non-NULL default values. the maximum length of TEXT is 2^16-1 characters, the maximum length of MEDIUMTEXT is 2^32-1 characters, and the maximum length of LONGTEXT is 2^64-1 characters.`,
			Case:     "CREATE TABLE `tbl` (`c` blob DEFAULT NULL);",
			Func:     (*Query4Audit).RuleBlobDefaultValue,
		},
		"COL.016": {
			Item:     "COL.016",
			Severity: "L1",
			Summary:  "INT(10) or BIGINT(20) is recommended for integer definitions",
			Content:  `INT(M) In the integer data type, M is the maximum display width. In INT(M), the value of M has nothing to do with how much storage space INT(M) takes up. INT(3), INT(4), and INT(8) all take up 4 bytes of storage space on disk. Higher versions of MySQL no longer recommend setting the integer display width.`,
			Case:     "CREATE TABLE tab (a INT(1));",
			Func:     (*Query4Audit).RuleIntPrecision,
		},
		"COL.017": {
			Item:     "COL.017",
			Severity: "L2",
			Summary:  "VARCHAR Definition length too long",
			Content:  fmt.Sprintf(`varchar is a variable-length string, no pre-allocated storage space, the length should not exceed %d, if the storage length is too long MySQL will define the field type as text, a separate table, with the primary key to correspond to avoid affecting the efficiency of other fields index.`, common.Config.MaxVarcharLength),
			Case:     "CREATE TABLE tab (a varchar(3500));",
			Func:     (*Query4Audit).RuleVarcharLength,
		},
		"COL.018": {
			Item:     "COL.018",
			Severity: "L9",
			Summary:  "The table build statement uses a field type that is not recommended",
			Content:  "The following field types are not recommended for use." + strings.Join(common.Config.ColumnNotAllowType, ", "),
			Case:     "CREATE TABLE tab (a BOOLEAN);",
			Func:     (*Query4Audit).RuleColumnNotAllowType,
		},
		"COL.019": {
			Item:     "COL.019",
			Severity: "L1",
			Summary:  "Time data types with precision below the second level are not recommended",
			Content:  "The use of high-precision time data types brings relatively large storage space consumption; MySQL can only support time data types accurate to microseconds in 5.6.4 or higher, so you need to consider version compatibility when using them.",
			Case:     "CREATE TABLE t1 (t TIME(3), dt DATETIME(6));",
			Func:     (*Query4Audit).RuleTimePrecision,
		},
		"DIS.001": {
			Item:     "DIS.001",
			Severity: "L1",
			Summary:  "Eliminate unnecessary DISTINCT conditions",
			Content:  `Too many DISTINCT conditions are a symptom of a complex wrap-around query. Consider breaking down complex queries into many simple queries and reducing the number of DISTINCT conditions. If the primary key column is part of the result set of the column, the DISTINCT condition may have no impact.`,
			Case:     "SELECT DISTINCT c.c_id,count(DISTINCT c.c_name),count(DISTINCT c.c_e),count(DISTINCT c.c_n),count(DISTINCT c.c_me),c.c_d FROM (select distinct id, name from B) as e WHERE e.country_id = c.country_id",
			Func:     (*Query4Audit).RuleDistinctUsage,
		},
		"DIS.002": {
			Item:     "DIS.002",
			Severity: "L3",
			Summary:  "COUNT(DISTINCT) may not be what you expect when you have multiple columns",
			Content:  `COUNT(DISTINCT col) counts the number of non-repeating rows in the column except NULL.`,
			Case:     "SELECT COUNT(DISTINCT col, col2) FROM tbl;",
			Func:     (*Query4Audit).RuleCountDistinctMultiCol,
		},
		// DIS.003 灵感来源于如下链接
		// http://www.ijstr.org/final-print/oct2015/Query-Optimization-Techniques-Tips-For-Writing-Efficient-And-Faster-Sql-Queries.pdf
		"DIS.003": {
			Item:     "DIS.003",
			Severity: "L3",
			Summary:  "DISTINCT * does not make sense for tables with primary keys",
			Content:  `When the table already has a primary key, the output of DISTINCT on all columns is the same as without the DISTINCT operation, so please do not add to it.`,
			Case:     "SELECT DISTINCT * FROM film;",
			Func:     (*Query4Audit).RuleDistinctStar,
		},
		"FUN.001": {
			Item:     "FUN.001",
			Severity: "L2",
			Summary:  "Avoid using functions or other operators in WHERE conditions",
			Content:  `Although using functions in SQL can simplify many complex queries, queries that use functions cannot take advantage of the indexes already established in the table, and the query will be a full table scan with poor performance. It is usually recommended to write the column names to the left of the comparison operator and put the query filter conditions to the right of the comparison operator. It is also not recommended to write extra parentheses on either side of the query comparison condition, which can be rather annoying to read.`,
			Case:     "select id from t where substring(name,1,3)='abc'",
			Func:     (*Query4Audit).RuleCompareWithFunction,
		},
		"FUN.002": {
			Item:     "FUN.002",
			Severity: "L1",
			Summary:  "COUNT(*) operation does not perform well when WHERE condition or non-MyISAM engine is specified",
			Content:  `COUNT(*) is used to count the number of rows in a table, while COUNT(COL) is used to count the number of rows in a specified column that are not NULL. MyISAM tables have special optimizations for COUNT(*) to count the number of rows in the whole table, which is usually very fast. However, for non-MyISAM tables or when certain WHERE conditions are specified, the COUNT(*) operation requires a large number of rows to be scanned to get an accurate result, and thus performance is poor. Sometimes some business scenarios don't need a completely accurate COUNT value, so you can use an approximation instead. the number of rows estimated by the optimizer out of EXPLAIN is a good approximation, and it's cheap to perform EXPLAIN without actually executing the query.`,
			Case:     "SELECT c3, COUNT(*) AS accounts FROM tab where c2 < 10000 GROUP BY c3 ORDER BY num",
			Func:     (*Query4Audit).RuleCountStar,
		},
		"FUN.003": {
			Item:     "FUN.003",
			Severity: "L3",
			Summary:  "String concatenation using merge into nullable columns",
			Content:  `In some query requests, you need to force a column or an expression to return a non-NULL value to make the query logic easier, but don't want to store the value. You can use the COALESCE() function to construct a concatenated expression so that even a null-valued column does not make the entire expression NULL.`,
			Case:     "select c1 || coalesce(' ' || c2 || ' ', ' ') || c3 as c from tbl",
			Func:     (*Query4Audit).RuleStringConcatenation,
		},
		"FUN.004": {
			Item:     "FUN.004",
			Severity: "L4",
			Summary:  "The SYSDATE() function is not recommended",
			Content:  `The SYSDATE() function may cause inconsistency between master and slave data, please use NOW() function instead of SYSDATE().`,
			Case:     "SELECT SYSDATE();",
			Func:     (*Query4Audit).RuleSysdate,
		},
		"FUN.005": {
			Item:     "FUN.005",
			Severity: "L1",
			Summary:  "It is not recommended to use COUNT(col) or COUNT(constant)",
			Content:  `Do not use COUNT(col) or COUNT(constant) instead of COUNT(*), which is the standard method of counting rows as defined by SQL92, independent of data and independent of NULL and non-NULL.`,
			Case:     "SELECT COUNT(1) FROM tbl;",
			Func:     (*Query4Audit).RuleCountConst,
		},
		"FUN.006": {
			Item:     "FUN.006",
			Severity: "L1",
			Summary:  "Note the NPE issue when using SUM(COL)",
			Content:  `When the value of a column is all NULL, COUNT(COL) returns 0, but SUM(COL) returns NULL, so you need to pay attention to the NPE problem when using SUM(). You can use the following way to avoid the NPE problem of SUM: SELECT IF(ISNULL(SUM(COL)), 0, SUM(COL)) FROM tbl`,
			Case:     "SELECT SUM(COL) FROM tbl;",
			Func:     (*Query4Audit).RuleSumNPE,
		},
		"FUN.007": {
			Item:     "FUN.007",
			Severity: "L1",
			Summary:  "Triggers are not recommended",
			Content:  `There is no feedback and log of trigger execution, which hides the actual execution steps. When there is a problem with the database, the specific execution of the trigger cannot be analyzed through the slow log, and it is not easy to find the problem. In My SQL, triggers cannot be closed or opened temporarily. In scenarios such as data migration or data recovery, triggers need to be dropped temporarily, which may affect the production environment.`,
			Case:     "CREATE TRIGGER t1 AFTER INSERT ON work FOR EACH ROW INSERT INTO time VALUES(NOW());",
			Func:     (*Query4Audit).RuleForbiddenTrigger,
		},
		"FUN.008": {
			Item:     "FUN.008",
			Severity: "L1",
			Summary:  "Stored procedures are not recommended",
			Content:  `Stored procedures have no version control, and it is difficult to upgrade stored procedures with the business in a business-aware manner. Stored procedures also have problems in expansion and migration.`,
			Case:     "CREATE PROCEDURE simpleproc (OUT param1 INT);",
			Func:     (*Query4Audit).RuleForbiddenProcedure,
		},
		"FUN.009": {
			Item:     "FUN.009",
			Severity: "L1",
			Summary:  "Custom functions are not recommended",
			Content:  `Custom functions are not recommended`,
			Case:     "CREATE FUNCTION hello (s CHAR(20));",
			Func:     (*Query4Audit).RuleForbiddenFunction,
		},
		"GRP.001": {
			Item:     "GRP.001",
			Severity: "L2",
			Summary:  "It is not recommended to use GROUP BY for equal-value query columns",
			Content:  `The columns in GROUP BY use an equivalence query in the preceding WHERE condition, and there is little point in GROUP BYing such columns.`,
			Case:     "select film_id, title from film where release_year='2006' group by release_year",
			Func:     (*Query4Audit).RuleOK, // 该建议在indexAdvisor中给 RuleGroupByConst
		},
		"JOI.001": {
			Item:     "JOI.001",
			Severity: "L2",
			Summary:  "JOIN statements mix commas and ANSI patterns",
			Content:  `Mixing commas and ANSI JOINs when joining tables is not easy for humans to understand, and different versions of MySQL have different table join behavior and priorities, which may introduce errors when MySQL versions change.`,
			Case:     "select c1,c2,c3 from t1,t2 join t3 on t1.c1=t2.c1,t1.c3=t3,c1 where id>1000",
			Func:     (*Query4Audit).RuleCommaAnsiJoin,
		},
		"JOI.002": {
			Item:     "JOI.002",
			Severity: "L4",
			Summary:  "The same table is joined twice",
			Content:  `The same table appears at least twice in the FROM clause, which can be simplified to a single access to that table.`,
			Case:     "select tb1.col from (tb1, tb2) join tb2 on tb1.id=tb.id where tb1.id=1",
			Func:     (*Query4Audit).RuleDupJoin,
		},
		"JOI.003": {
			Item:     "JOI.003",
			Severity: "L4",
			Summary:  "OUTER JOIN is not working",
			Content:  `This implicitly converts the query to an INNER JOIN because the WHERE condition is wrong and no data is returned from the external table of the OUTER JOIN. For example: select c from L left join R using(c) where L.a=5 and R.b=10. There may be a logical error or programmer misunderstanding of how OUTER JOIN works because LEFT/RIGHT JOIN is short for LEFT/RIGHT OUTER JOIN.`,
			Case:     "select c1,c2,c3 from t1 left outer join t2 using(c1) where t1.c2=2 and t2.c3=4",
			Func:     (*Query4Audit).RuleOK, // TODO
		},
		"JOI.004": {
			Item:     "JOI.004",
			Severity: "L4",
			Summary:  "It is not recommended to use exclusive JOIN",
			Content:  `A LEFT OUTER JOIN statement with a WHERE clause with NULL in the right-hand table only could be using the wrong column in the WHERE clause, e.g., "... FROM l LEFT OUTER JOIN r ON l.l = r.r WHERE r.z IS NULL", the correct logic for this query might be WHERE r.r IS NULL.`,
			Case:     "select c1,c2,c3 from t1 left outer join t2 on t1.c1=t2.c1 where t2.c2 is null",
			Func:     (*Query4Audit).RuleOK, // TODO
		},
		"JOI.005": {
			Item:     "JOI.005",
			Severity: "L2",
			Summary:  "Reduce the number of JOINs",
			Content:  `Too many JOINs is a symptom of a complex wrap-around query. Consider breaking down complex queries into many simple queries and reducing the number of JOINs.`,
			Case:     "select bp1.p_id, b1.d_d as l, b1.b_id from b1 join bp1 on (b1.b_id = bp1.b_id) left outer join (b1 as b2 join bp2 on (b2.b_id = bp2.b_id)) on (bp1.p_id = bp2.p_id ) join bp21 on (b1.b_id = bp1.b_id) join bp31 on (b1.b_id = bp1.b_id) join bp41 on (b1.b_id = bp1.b_id) where b2.b_id = 0",
			Func:     (*Query4Audit).RuleReduceNumberOfJoin,
		},
		"JOI.006": {
			Item:     "JOI.006",
			Severity: "L4",
			Summary:  "Rewriting nested queries as JOINs often results in more efficient execution and more effective optimization",
			Content:  `In general, non-nested subqueries are always used for related subqueries, up to one table from the FROM clause, which are used for ANY, ALL and EXISTS predicates. An unrelated subquery or a subquery from multiple tables in a FROM clause is flattened if the subquery can be determined to return at most one row based on the query semantics.`,
			Case:     "SELECT s,p,d FROM tbl WHERE p.p_id = (SELECT s.p_id FROM tbl WHERE s.c_id = 100996 AND s.q = 1 )",
			Func:     (*Query4Audit).RuleNestedSubQueries,
		},
		"JOI.007": {
			Item:     "JOI.007",
			Severity: "L4",
			Summary:  "It is not recommended to use join table deletion or update",
			Content:  `When you need to delete or update multiple tables at the same time, it is recommended to use simple statements, one SQL only delete or update one table, and try not to operate on multiple tables in the same statement.`,
			Case:     "UPDATE users u LEFT JOIN hobby h ON u.id = h.uid SET u.name = 'pianoboy' WHERE h.hobby = 'piano';",
			Func:     (*Query4Audit).RuleMultiDeleteUpdate,
		},
		"JOI.008": {
			Item:     "JOI.008",
			Severity: "L4",
			Summary:  "Do not use JOIN queries across databases",
			Content:  `In general, a cross-database JOIN query implies that the query statement spans two different subsystems, which may mean that the system is too coupled or the library table structure is not well designed.`,
			Case:     "SELECT s,p,d FROM tbl WHERE p.p_id = (SELECT s.p_id FROM tbl WHERE s.c_id = 100996 AND s.q = 1 )",
			Func:     (*Query4Audit).RuleMultiDBJoin,
		},
		// TODO: 跨库事务的检查，目前SOAR未对事务做处理
		"KEY.001": {
			Item:     "KEY.001",
			Severity: "L2",
			Summary:  "It is recommended to use self-incrementing column as primary key, if you use joint self-incrementing primary key, please use self-incrementing key as the first column",
			Content:  `It is recommended to use self-incrementing column as primary key, if you use joint self-incrementing primary key, please use self-incrementing key as the first column`,
			Case:     "create table test(`id` int(11) NOT NULL PRIMARY KEY (`id`))",
			Func:     (*Query4Audit).RulePKNotInt,
		},
		"KEY.002": {
			Item:     "KEY.002",
			Severity: "L4",
			Summary:  "No primary key or unique key, no online change of table structure",
			Content:  `No primary key or unique key, no online change of table structure`,
			Case:     "create table test(col varchar(5000))",
			Func:     (*Query4Audit).RuleNoOSCKey,
		},
		"KEY.003": {
			Item:     "KEY.003",
			Severity: "L4",
			Summary:  "Avoid recursive relationships such as foreign keys",
			Content:  `It is common for data with recursive relationships to exist, and data is often organized like a tree or in a hierarchical fashion. However, creating a foreign key constraint to enforce a relationship between two columns in the same table can lead to clumsy queries. Each level of the tree corresponds to another join. You will need to issue a recursive query to get all descendants or all ancestors of a node. The solution is to construct an additional closure table. It records the relationships between all nodes in the tree, not just those with direct parent-child relationships. You can also compare different levels of data design: closure tables, path enumerations, nested sets. Then choose one according to the needs of your application.`,
			Case:     "CREATE TABLE tab2 (p_id  BIGINT UNSIGNED NOT NULL,a_id  BIGINT UNSIGNED NOT NULL,PRIMARY KEY (p_id, a_id),FOREIGN KEY (p_id) REFERENCES tab1(p_id),FOREIGN KEY (a_id) REFERENCES tab3(a_id))",
			Func:     (*Query4Audit).RuleRecursiveDependency,
		},
		// TODO: 新增复合索引，字段按散粒度是否由大到小排序，区分度最高的在最左边
		"KEY.004": {
			Item:     "KEY.004",
			Severity: "L0",
			Summary:  "Reminder: Please align the index property order with the query",
			Content:  `If creating a composite index for a column, make sure that the query attributes are in the same order as the index attributes so that the DBMS can use the index during query processing. If the query and index attribute orders are not aligned, then the DBMS may not be able to use the index during query processing.`,
			Case:     "create index idx1 on tbl (last_name,first_name)",
			Func:     (*Query4Audit).RuleIndexAttributeOrder,
		},
		"KEY.005": {
			Item:     "KEY.005",
			Severity: "L2",
			Summary:  "Too many indexes on tables",
			Content:  `Too many indexes on tables`,
			Case:     "CREATE TABLE tbl ( a int, b int, c int, KEY idx_a (`a`),KEY idx_b(`b`),KEY idx_c(`c`));",
			Func:     (*Query4Audit).RuleTooManyKeys,
		},
		"KEY.006": {
			Item:     "KEY.006",
			Severity: "L4",
			Summary:  "Too many columns in the primary key",
			Content:  `Too many columns in the primary key`,
			Case:     "CREATE TABLE tbl ( a int, b int, c int, PRIMARY KEY(`a`,`b`,`c`));",
			Func:     (*Query4Audit).RuleTooManyKeyParts,
		},
		"KEY.007": {
			Item:     "KEY.007",
			Severity: "L4",
			Summary:  "No primary key is specified or the primary key is not int or bigint",
			Content:  `If no primary key is specified or the primary key is not int or bigint, it is recommended to set the primary key to int unsigned or bigint unsigned.`,
			Case:     "CREATE TABLE tbl (a int);",
			Func:     (*Query4Audit).RulePKNotInt,
		},
		"KEY.008": {
			Item:     "KEY.008",
			Severity: "L4",
			Summary:  "ORDER BY multiple columns with different sort directions may not work with indexes",
			Content:  `Prior to MySQL 8.0, established indexes could not be used when ORDER BY multiple columns specified different sort directions.`,
			Case:     "SELECT * FROM tbl ORDER BY a DESC, b ASC;",
			Func:     (*Query4Audit).RuleOrderByMultiDirection,
		},
		"KEY.009": {
			Item:     "KEY.009",
			Severity: "L0",
			Summary:  "Please take care to check data uniqueness before adding unique indexes",
			Content:  `Please check the data uniqueness of the added unique index columns in advance, if the data is not unique, the duplicate columns will likely be automatically removed when the online table is restructured, which may lead to data loss.`,
			Case:     "CREATE UNIQUE INDEX part_of_name ON customer (name(10));",
			Func:     (*Query4Audit).RuleUniqueKeyDup,
		},
		"KEY.010": {
			Item:     "KEY.010",
			Severity: "L0",
			Summary:  "Full text index is not a silver bullet",
			Content:  `Full-text indexing is mainly used to solve the performance problem of fuzzy queries, but you need to control the frequency and concurrency of queries. Also pay attention to adjusting parameters such as ft_min_word_len, ft_max_word_len, ngram_token_size, etc.`,
			Case:     "CREATE TABLE `tb` ( `id` int(10) unsigned NOT NULL AUTO_INCREMENT, `ip` varchar(255) NOT NULL DEFAULT '', PRIMARY KEY (`id`), FULLTEXT KEY `ip` (`ip`) ) ENGINE=InnoDB;",
			Func:     (*Query4Audit).RuleFulltextIndex,
		},
		"KWR.001": {
			Item:     "KWR.001",
			Severity: "L2",
			Summary:  "SQL_CALC_FOUND_ROWS Inefficient",
			Content:  `Because SQL_CALC_FOUND_ROWS does not scale well, it may cause performance problems; it is recommended that the business use other strategies to replace the counting functions provided by SQL_CALC_FOUND_ROWS, e.g., paged results display, etc.`,
			Case:     "select SQL_CALC_FOUND_ROWS col from tbl where id>1000",
			Func:     (*Query4Audit).RuleSQLCalcFoundRows,
		},
		"KWR.002": {
			Item:     "KWR.002",
			Severity: "L2",
			Summary:  "It is not recommended to use MySQL keywords for column names or table names",
			Content:  `When using keywords as column names or table names the program needs to escape the column names and table names, if omitted the request will not be executed.`,
			Case:     "CREATE TABLE tbl ( `select` int )",
			Func:     (*Query4Audit).RuleUseKeyWord,
		},
		"KWR.003": {
			Item:     "KWR.003",
			Severity: "L1",
			Summary:  "It is not recommended to use plural as column or table names",
			Content:  `The table name should only indicate the content of the entities inside the table, not the number of entities, and the corresponding DO class name is also in singular form, in line with the expression convention.`,
			Case:     "CREATE TABLE tbl ( `books` int )",
			Func:     (*Query4Audit).RulePluralWord,
		},
		"KWR.004": {
			Item:     "KWR.004",
			Severity: "L1",
			Summary:  "Naming with multi-byte encoded characters (Chinese) is not recommended",
			Content:  `When naming libraries, tables, columns, and aliases, it is recommended to use English, numeric, underscore, and other characters, not Chinese or other multi-byte encoded characters.`,
			Case:     "select col as 列 from tb",
			Func:     (*Query4Audit).RuleMultiBytesWord,
		},
		"KWR.005": {
			Item:     "KWR.005",
			Severity: "L1",
			Summary:  "SQL contains unicode special characters",
			Content:  "Some IDEs automatically insert invisible unicode characters in SQL, such as non-break space, zero-width space, etc. You can use `cat -A file.sql` command in Linux to see the invisible characters.",
			Case:     "update tb set status = 1 where id = 1;",
			Func:     (*Query4Audit).RuleInvisibleUnicode,
		},
		"LCK.001": {
			Item:     "LCK.001",
			Severity: "L3",
			Summary:  "INSERT INTO xx SELECT locking granularity is large, please be careful",
			Content:  `INSERT INTO xx SELECT locking granularity is large, please be careful`,
			Case:     "INSERT INTO tbl SELECT * FROM tbl2;",
			Func:     (*Query4Audit).RuleInsertSelect,
		},
		"LCK.002": {
			Item:     "LCK.002",
			Severity: "L3",
			Summary:  "Please use INSERT ON DUPLICATE KEY UPDATE with caution.",
			Content:  `Using INSERT ON DUPLICATE KEY UPDATE when the primary key is a self-incrementing key may result in a large number of discontinuous fast-growing primary keys, causing the primary key to overflow too fast to continue writing. In extreme cases, it may also lead to inconsistent master-slave data.`,
			Case:     "INSERT INTO t1(a,b,c) VALUES (1,2,3) ON DUPLICATE KEY UPDATE c=c+1;",
			Func:     (*Query4Audit).RuleInsertOnDup,
		},
		"LIT.001": {
			Item:     "LIT.001",
			Severity: "L2",
			Summary:  "Storing IP addresses with character types",
			Content:  `A string that literally looks like an IP address but is not an argument to INET_ATON() indicates that the data is stored as a character rather than an integer. It is more efficient to store IP addresses as integers.`,
			Case:     "insert into tbl (IP,name) values('10.20.306.122','test')",
			Func:     (*Query4Audit).RuleIPString,
		},
		"LIT.002": {
			Item:     "LIT.002",
			Severity: "L4",
			Summary:  "Date/time not enclosed in quotation marks",
			Content:  `A query such as "WHERE col <2010-02-12" is valid SQL, but may be an error because it will be interpreted as "WHERE col <1996"; the date/time text should be in quotation marks. and there should be no spaces before or after the quotes.`,
			Case:     "select col1,col2 from tbl where time < 2018-01-10",
			Func:     (*Query4Audit).RuleDateNotQuote,
		},
		"LIT.003": {
			Item:     "LIT.003",
			Severity: "L3",
			Summary:  "A collection of related data stored in a column",
			Content:  `Storing IDs as a list as VARCHAR/TEXT columns can lead to performance and data integrity problems. Querying such columns requires the use of pattern matching expressions. Using a comma-separated list to do a multi-table join query to locate a row of data is extremely inelegant and time-consuming. This makes it more difficult to validate IDs. Consider this: What is the maximum amount of data that a list can hold? Instead of using multi-valued attributes, store the IDs in a separate table so that each individual attribute value can occupy a row. This way the cross table implements a many-to-many relationship between the two tables. This will simplify queries better and also validate IDs more efficiently.`,
			Case:     "select c1,c2,c3,c4 from tab1 where col_id REGEXP '[[:<:]]12[[:>:]]'",
			Func:     (*Query4Audit).RuleMultiValueAttribute,
		},
		"LIT.004": {
			Item:     "LIT.004",
			Severity: "L1",
			Summary:  "Please use a semicolon or a set DELIMITER ending",
			Content:  `The commands USE database, SHOW DATABASES, etc. also require a semicolon or a set DELIMITER ending.`,
			Case:     "USE db",
			Func:     (*Query4Audit).RuleOK, // TODO: RuleAddDelimiter
		},
		"RES.001": {
			Item:     "RES.001",
			Severity: "L4",
			Summary:  "Non-deterministic GROUP BY",
			Content:  `The columns returned by the SQL are neither in the aggregation function nor in the columns of the GROUP BY expression, so the result of these values will be non-deterministic. For example: select a, b, c from tbl where foo="bar" group by a, the result returned by this SQL is non-deterministic.`,
			Case:     "select c1,c2,c3 from t1 where c2='foo' group by c2",
			Func:     (*Query4Audit).RuleNoDeterministicGroupby,
		},
		"RES.002": {
			Item:     "RES.002",
			Severity: "L4",
			Summary:  "LIMIT queries that do not use ORDER BY",
			Content:  `LIMIT without ORDER BY leads to non-deterministic results, depending on the query execution plan.`,
			Case:     "select col1,col2 from tbl where name=xx limit 10",
			Func:     (*Query4Audit).RuleNoDeterministicLimit,
		},
		"RES.003": {
			Item:     "RES.003",
			Severity: "L4",
			Summary:  "The UPDATE/DELETE operation uses the LIMIT condition",
			Content:  `UPDATE/DELETE operations using the LIMIT condition are just as dangerous as not adding the WHERE condition, which can lead to master-slave data inconsistencies or broken slave synchronization.`,
			Case:     "UPDATE film SET length = 120 WHERE title = 'abc' LIMIT 1;",
			Func:     (*Query4Audit).RuleUpdateDeleteWithLimit,
		},
		"RES.004": {
			Item:     "RES.004",
			Severity: "L4",
			Summary:  "The UPDATE/DELETE operation specifies the ORDER BY condition",
			Content:  `Do not specify an ORDER BY condition for UPDATE/DELETE operations.`,
			Case:     "UPDATE film SET length = 120 WHERE title = 'abc' ORDER BY title",
			Func:     (*Query4Audit).RuleUpdateDeleteWithOrderby,
		},
		"RES.005": {
			Item:     "RES.005",
			Severity: "L4",
			Summary:  "The UPDATE statement may have a logical error, resulting in data corruption",
			Content:  "In a UPDATE statement, if multiple fields are to be updated, the fields should not be separated by ANDs, but by commas.",
			Case:     "update tbl set col = 1 and cl = 2 where col=3;",
			Func:     (*Query4Audit).RuleUpdateSetAnd,
		},
		"RES.006": {
			Item:     "RES.006",
			Severity: "L4",
			Summary:  "Never really compare conditions",
			Content:  "The query condition is always not true, and if it appears in a where, it may result in a query with no matched results.",
			Case:     "select * from tbl where 1 != 1;",
			Func:     (*Query4Audit).RuleImpossibleWhere,
		},
		"RES.007": {
			Item:     "RES.007",
			Severity: "L4",
			Summary:  "Always compare conditions for true",
			Content:  "The query condition is always true, which may cause the WHERE condition to fail for a full table query.",
			Case:     "select * from tbl where 1 = 1;",
			Func:     (*Query4Audit).RuleMeaninglessWhere,
		},
		"RES.008": {
			Item:     "RES.008",
			Severity: "L2",
			Summary:  "It is not recommended to use LOAD DATA/SELECT ... INTO OUTFILE",
			Content:  "SELECT INTO OUTFILE requires FILE permissions, which can introduce security issues. load DATA can increase the speed of data import, but it can also cause excessive delays in synchronizing from the library.",
			Case:     "LOAD DATA INFILE 'data.txt' INTO TABLE db2.my_table;",
			Func:     (*Query4Audit).RuleLoadFile,
		},
		"RES.009": {
			Item:     "RES.009",
			Severity: "L2",
			Summary:  "Continuous judgment is not recommended",
			Content:  "A statement like this SELECT * FROM tbl WHERE col = col = 'abc' may be a writing error and you may want to convey that col = 'abc'. If this is indeed a business requirement it is recommended to change it to col = col and col = 'abc'.",
			Case:     "SELECT * FROM tbl WHERE col = col = 'abc'",
			Func:     (*Query4Audit).RuleMultiCompare,
		},
		"RES.010": {
			Item:     "RES.010",
			Severity: "L2",
			Summary:  "The fields defined as ON UPDATE CURRENT_TIMESTAMP in the table build statement are not recommended to contain business logic",
			Content:  "A field defined as ON UPDATE CURRENT_TIMESTAMP will be modified when other fields in the table are updated, which can be a problem if it contains business logic that is visible to the user. This could lead to data errors if there are subsequent bulk changes to the data but you don't want to modify the field.",
			Case:     `CREATE TABLE category (category_id TINYINT UNSIGNED NOT NULL AUTO_INCREMENT,	name VARCHAR(25) NOT NULL, last_update TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, PRIMARY KEY  (category_id)`,
			Func:     (*Query4Audit).RuleCreateOnUpdate,
		},
		"RES.011": {
			Item:     "RES.011",
			Severity: "L2",
			Summary:  "The table for the update request operation contains the ON UPDATE CURRENT_TIMESTAMP field",
			Content:  "The field defined as ON UPDATE CURRENT_TIMESTAMP will be changed when other fields in the table are updated, so please check this. If you do not want to change the update time of the field you can use the following method: UPDATE category SET name='ActioN', last_update=last_update WHERE category_id=1",
			Case:     "UPDATE category SET name='ActioN', last_update=last_update WHERE category_id=1",
			Func:     (*Query4Audit).RuleOK, // 该建议在indexAdvisor中给 RuleUpdateOnUpdate
		},
		"SEC.001": {
			Item:     "SEC.001",
			Severity: "L0",
			Summary:  "Please use TRUNCATE operation with caution",
			Content:  `Generally speaking, the quickest way to empty a table is to use the TRUNCATE TABLE tbl_name; statement. However, the TRUNCATE operation is not without cost. TRUNCATE TABLE does not return the exact number of rows deleted, so if you need to return the number of rows deleted, it is recommended that you use the DELETE syntax. The TRUNCATE operation adds a source data lock (MDL) to the data dictionary, which affects all requests for the entire instance when many tables need to be TRUNCATE at once, so it is recommended to use DROP+CREATE to reduce the lock time if multiple tables are to be TRUNCATE.`,
			Case:     "TRUNCATE TABLE tbl_name",
			Func:     (*Query4Audit).RuleTruncateTable,
		},
		"SEC.002": {
			Item:     "SEC.002",
			Severity: "L0",
			Summary:  "Do not use plaintext to store passwords",
			Content:  `It is not secure to use plaintext to store passwords or to use plaintext to pass pass passwords over the network. If an attacker is able to intercept the SQL statement you use to insert the password, they will be able to read it directly. Alternatively, inserting a user-entered string in plaintext into a plain SQL statement would allow an attacker to discover it. If you can read the password, so can a hacker. The solution is to cryptographically encode the original password using a one-way hash function. A hash is a function that transforms the input string into another new, unrecognizable string. Add some random strings to the password encryption expression to defend against "dictionary attacks". Do not enter plaintext passwords into SQL query statements. Calculate the hash string in the application code and use it only in SQL queries.`,
			Case:     "create table test(id int,name varchar(20) not null,password varchar(200)not null)",
			Func:     (*Query4Audit).RuleReadablePasswords,
		},
		"SEC.003": {
			Item:     "SEC.003",
			Severity: "L0",
			Summary:  "Take care of backup when using DELETE/DROP/TRUNCATE, etc.",
			Content:  `It is essential to back up your data before performing high-risk operations.`,
			Case:     "delete from table where col = 'condition'",
			Func:     (*Query4Audit).RuleDataDrop,
		},
		"SEC.004": {
			Item:     "SEC.004",
			Severity: "L0",
			Summary:  "Discover common SQL injection functions",
			Content:  `Functions such as SLEEP(), BENCHMARK(), GET_LOCK(), RELEASE_LOCK(), etc. are usually found in SQL injection statements and can seriously affect database performance.`,
			Case:     "SELECT BENCHMARK(10, RAND())",
			Func:     (*Query4Audit).RuleInjection,
		},
		"STA.001": {
			Item:     "STA.001",
			Severity: "L0",
			Summary:  "The '!=' operator is a non-standard",
			Content:  `It is "<>" that is the not-equal operator in standard SQL.`,
			Case:     "select col1,col2 from tbl where type!=0",
			Func:     (*Query4Audit).RuleStandardINEQ,
		},
		"STA.002": {
			Item:     "STA.002",
			Severity: "L1",
			Summary:  "No spaces are recommended after the library or table names",
			Content:  `When accessing a table or field using the db.table or table.column format, do not add spaces after the dot, although this is syntactically correct.`,
			Case:     "select col from sakila. film",
			Func:     (*Query4Audit).RuleSpaceAfterDot,
		},
		"STA.003": {
			Item:     "STA.003",
			Severity: "L1",
			Summary:  "Claim caused by the name is not standardized",
			Content:  `It is recommended that the general secondary indexing starts with` + common.Config.IdxPrefix + `is prefixed, and the unique index is prefixed with` + common.Config.UkPrefix + `for the prefix.`,
			Case:     "select col from now where type!=0",
			Func:     (*Query4Audit).RuleIdxPrefix,
		},
		"STA.004": {
			Item:     "STA.004",
			Severity: "L1",
			Summary:  "Please do not use letters, numbers and underscores in your name",
			Content:  `Start with a letter or underscore, only letters, numbers and underscores are allowed in names. Please standardize case and do not use camel nomenclature. Do not have consecutive underscores '__' in your name, as it is difficult to identify.`,
			Case:     "CREATE TABLE ` abc` (a int);",
			Func:     (*Query4Audit).RuleStandardName,
		},
		"SUB.001": {
			Item:     "SUB.001",
			Severity: "L4",
			Summary:  "MySQL's Poor Optimization of Subqueries",
			Content:  `MySQL executes subqueries as dependent subqueries for each row in an external query. This is a common cause of serious performance problems. This may be improved in MySQL 5.6, but for 5.1 and earlier, it is recommended that such queries be rewritten as JOIN or LEFT OUTER JOIN, respectively.`,
			Case:     "select col1,col2,col3 from table1 where col2 in(select col from table2)",
			Func:     (*Query4Audit).RuleInSubquery,
		},
		"SUB.002": {
			Item:     "SUB.002",
			Severity: "L2",
			Summary:  "If you don't care about duplication, it is recommended to use UNION ALL instead of UNION",
			Content:  `Unlike UNION, which removes duplicates, UNION ALL allows duplicate tuples. If you don't care about duplicate tuples, then using UNION ALL would be a faster option.`,
			Case:     "select teacher_id as id,people_name as name from t1,t2 where t1.teacher_id=t2.people_id union select student_id as id,people_name as name from t1,t2 where t1.student_id=t2.people_id",
			Func:     (*Query4Audit).RuleUNIONUsage,
		},
		"SUB.003": {
			Item:     "SUB.003",
			Severity: "L3",
			Summary:  "Consider using EXISTS instead of DISTINCT subqueries",
			Content:  `The DISTINCT keyword removes duplicates after sorting the tuple. Instead, consider using a subquery with the EXISTS keyword and you can avoid returning the entire table.`,
			Case:     "SELECT DISTINCT c.c_id, c.c_name FROM c,e WHERE e.c_id = c.c_id",
			Func:     (*Query4Audit).RuleDistinctJoinUsage,
		},
		// TODO: 5.6有了semi join 还要把 in 转成 exists 么？
		// Use EXISTS instead of IN to check existence of data.
		// http://www.winwire.com/25-tips-to-improve-sql-query-performance/
		"SUB.004": {
			Item:     "SUB.004",
			Severity: "L3",
			Summary:  "The nested join depth in the execution plan is too deep",
			Content:  `MySQL does not optimize subqueries well,MySQL executes subqueries as dependent subqueries for each row in an external query. This is a common cause of serious performance problems.`,
			Case:     "SELECT * from tb where id in (select id from (select id from tb))",
			Func:     (*Query4Audit).RuleSubqueryDepth,
		},
		// SUB.005灵感来自 https://blog.csdn.net/zhuocr/article/details/61192418
		"SUB.005": {
			Item:     "SUB.005",
			Severity: "L8",
			Summary:  "Subqueries do not support LIMIT",
			Content:  `The current MySQL version does not support 'LIMIT & IN/ALL/ANY/SOME' in subqueries.`,
			Case:     "SELECT * FROM staff WHERE name IN (SELECT NAME FROM customer ORDER BY name LIMIT 1)",
			Func:     (*Query4Audit).RuleSubQueryLimit,
		},
		"SUB.006": {
			Item:     "SUB.006",
			Severity: "L2",
			Summary:  "It is not recommended to use functions in subqueries",
			Content:  `MySQL executes subqueries as dependent subqueries for each row in an external query. If you use functions in subqueries, it is difficult to perform efficient queries even with semi-join. You can rewrite the subquery as an OUTER JOIN statement and filter the data with join conditions.`,
			Case:     "SELECT * FROM staff WHERE name IN (SELECT max(NAME) FROM customer)",
			Func:     (*Query4Audit).RuleSubQueryFunctions,
		},
		"SUB.007": {
			Item:     "SUB.007",
			Severity: "L2",
			Summary:  "UNION union queries with LIMIT output limits on the outer level are recommended to have LIMIT output limits added to their inner level queries as well",
			Content:  `Sometimes MySQL cannot "push down" the restriction from the outer level to the inner level, which can prevent conditions that would otherwise restrict the ability to restrict some of the returned results from being applied to the inner query optimization. For example: (SELECT * FROM tb1 ORDER BY name) UNION ALL (SELECT * FROM tb2 ORDER BY name) LIMIT 20; MySQL will put the results of two subqueries in a temporary table and then take 20 results, which can be reduced by adding LIMIT 20 to the two subqueries. You can reduce the data in the temporary table by adding LIMIT 20 to both subqueries. (SELECT * FROM tb1 ORDER BY name LIMIT 20) UNION ALL (SELECT * FROM tb2 ORDER BY name LIMIT 20) LIMIT 20;`,
			Case:     "(SELECT * FROM tb1 ORDER BY name LIMIT 20) UNION ALL (SELECT * FROM tb2 ORDER BY name LIMIT 20) LIMIT 20;",
			Func:     (*Query4Audit).RuleUNIONLimit,
		},
		"TBL.001": {
			Item:     "TBL.001",
			Severity: "L4",
			Summary:  "Partitioned tables are not recommended",
			Content:  `Partitioned tables are not recommended`,
			Case:     "CREATE TABLE trb3(id INT, name VARCHAR(50), purchased DATE) PARTITION BY RANGE(YEAR(purchased)) (PARTITION p0 VALUES LESS THAN (1990), PARTITION p1 VALUES LESS THAN (1995), PARTITION p2 VALUES LESS THAN (2000), PARTITION p3 VALUES LESS THAN (2005) );",
			Func:     (*Query4Audit).RulePartitionNotAllowed,
		},
		"TBL.002": {
			Item:     "TBL.002",
			Severity: "L4",
			Summary:  "Please select the appropriate storage engine for the table",
			Content:  `It is recommended to use the recommended storage engine when building or modifying tables, e.g.` + strings.Join(common.Config.AllowEngines, ","),
			Case:     "create table test(`id` int(11) NOT NULL AUTO_INCREMENT)",
			Func:     (*Query4Audit).RuleAllowEngine,
		},
		"TBL.003": {
			Item:     "TBL.003",
			Severity: "L8",
			Summary:  "Tables named after DUAL have special meanings in the database",
			Content:  `DUAL table is a virtual table, which can be used without creating, and it is not recommended that the service name the table with DUAL.`,
			Case:     "create table dual(id int, primary key (id));",
			Func:     (*Query4Audit).RuleCreateDualTable,
		},
		"TBL.004": {
			Item:     "TBL.004",
			Severity: "L2",
			Summary:  "The initial AUTO INCREMENT value of the table is not 0",
			Content:  `AUTO INCREMENT not being 0 will result in data voids.`,
			Case:     "CREATE TABLE tbl (a int) AUTO_INCREMENT = 10;",
			Func:     (*Query4Audit).RuleAutoIncrementInitNotZero,
		},
		"TBL.005": {
			Item:     "TBL.005",
			Severity: "L4",
			Summary:  "Please use the recommended character set",
			Content:  `Table character sets are only allowed to be set to '` + strings.Join(common.Config.AllowCharsets, ",") + "'",
			Case:     "CREATE TABLE tbl (a int) DEFAULT CHARSET = latin1;",
			Func:     (*Query4Audit).RuleTableCharsetCheck,
		},
		"TBL.006": {
			Item:     "TBL.006",
			Severity: "L1",
			Summary:  "View is not recommended",
			Content:  `View is not recommended`,
			Case:     "create view v_today (today) AS SELECT CURRENT_DATE;",
			Func:     (*Query4Audit).RuleForbiddenView,
		},
		"TBL.007": {
			Item:     "TBL.007",
			Severity: "L1",
			Summary:  "Temporary tables are not recommended",
			Content:  `Temporary tables are not recommended`,
			Case:     "CREATE TEMPORARY TABLE `work` (`time` time DEFAULT NULL) ENGINE=InnoDB;",
			Func:     (*Query4Audit).RuleForbiddenTempTable,
		},
		"TBL.008": {
			Item:     "TBL.008",
			Severity: "L4",
			Summary:  "Please use the recommended COLLATE",
			Content:  `COLLATE is only allowed to be set to '` + strings.Join(common.Config.AllowCollates, ",") + "'",
			Case:     "CREATE TABLE tbl (a int) DEFAULT COLLATE = latin1_bin;",
			Func:     (*Query4Audit).RuleTableCharsetCheck,
		},
	}
}

// IsIgnoreRule 判断是否是过滤规则
// 支持XXX*前缀匹配，OK规则不可设置过滤
func IsIgnoreRule(item string) bool {

	for _, ir := range common.Config.IgnoreRules {
		ir = strings.Trim(ir, "*")
		if strings.HasPrefix(item, ir) && ir != "OK" && ir != "" {
			common.Log.Debug("IsIgnoreRule: %s", item)
			return true
		}
	}
	return false
}

// InBlackList 判断一条请求是否在黑名单列表中
// 如果在返回true，表示不需要评审
// 注意这里没有做指纹判断，是否用指纹在这个函数的外面处理
func InBlackList(sql string) bool {
	in := false
	for _, r := range common.BlackList {
		if sql == r {
			in = true
			break
		}
		re, err := regexp.Compile("(?i)" + r)
		if err == nil {
			if re.FindString(sql) != "" {
				common.Log.Debug("InBlackList: true, regexp: %s, sql: %s", "(?i)"+r, sql)
				in = true
				break
			}
			common.Log.Debug("InBlackList: false, regexp: %s, sql: %s", "(?i)"+r, sql)
		}
	}
	return in
}

// FormatSuggest 格式化输出优化建议
func FormatSuggest(sql string, currentDB string, format string, suggests ...map[string]Rule) (map[string]Rule, string) {
	common.Log.Debug("FormatSuggest, Query: %s", sql)
	var fingerprint, id string
	var buf []string
	var score = 100
	type Result struct {
		ID          string
		Fingerprint string
		Sample      string
		Suggest     map[string]Rule
	}

	// 生成指纹和ID
	if sql != "" {
		fingerprint = query.Fingerprint(sql)
		id = query.Id(fingerprint)
	}

	// 合并重复的建议
	suggest := make(map[string]Rule)
	for _, s := range suggests {
		for item, rule := range s {
			suggest[item] = rule
		}
	}
	suggest = MergeConflictHeuristicRules(suggest)

	// 是否忽略显示OK建议，测试的时候大家都喜欢看OK，线上跑起来的时候OK太多反而容易看花眼
	ignoreOK := false
	for _, r := range common.Config.IgnoreRules {
		if "OK" == r {
			ignoreOK = true
		}
	}

	// 先保证suggest中有元素，然后再根据ignore配置删除不需要的项
	if len(suggest) < 1 {
		suggest = map[string]Rule{"OK": HeuristicRules["OK"]}
	}
	if ignoreOK || len(suggest) > 1 {
		delete(suggest, "OK")
	}
	for k := range suggest {
		if IsIgnoreRule(k) {
			delete(suggest, k)
		}
	}
	common.Log.Debug("FormatSuggest, format: %s", format)
	switch format {
	case "json":
		buf = append(buf, formatJSON(sql, currentDB, suggest))

	case "text":
		for item, rule := range suggest {
			buf = append(buf, fmt.Sprintln("Query: ", sql))
			buf = append(buf, fmt.Sprintln("ID: ", id))
			buf = append(buf, fmt.Sprintln("Item: ", item))
			buf = append(buf, fmt.Sprintln("Severity: ", rule.Severity))
			buf = append(buf, fmt.Sprintln("Summary: ", rule.Summary))
			buf = append(buf, fmt.Sprintln("Content: ", rule.Content))
		}
	case "lint":
		for item, rule := range suggest {
			// lint 中无需关注 OK 和 EXP
			if item != "OK" && !strings.HasPrefix(item, "EXP") {
				buf = append(buf, fmt.Sprintf("%s %s", item, rule.Summary))
			}
		}

	case "markdown", "html", "explain-digest", "duplicate-key-checker":
		if sql != "" && len(suggest) > 0 {
			switch common.Config.ExplainSQLReportType {
			case "fingerprint":
				buf = append(buf, fmt.Sprintf("# Query: %s\n", id))
				buf = append(buf, fmt.Sprintf("```sql\n%s\n```\n", fingerprint))
			case "sample":
				buf = append(buf, fmt.Sprintf("# Query: %s\n", id))
				buf = append(buf, fmt.Sprintf("```sql\n%s\n```\n", sql))
			default:
				buf = append(buf, fmt.Sprintf("# Query: %s\n", id))
				buf = append(buf, fmt.Sprintf("```sql\n%s\n```\n", ast.Pretty(sql, format)))
			}
		}
		// MySQL
		common.Log.Debug("FormatSuggest, start of sortedMySQLSuggest")
		var sortedMySQLSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "ERR") {
				if suggest[item].Content == "" {
					delete(suggest, item)
				} else {
					sortedMySQLSuggest = append(sortedMySQLSuggest, item)
				}
			}
		}
		sort.Strings(sortedMySQLSuggest)
		if len(sortedMySQLSuggest) > 0 {
			buf = append(buf, "## MySQL execute failed\n")
		}
		for _, item := range sortedMySQLSuggest {
			buf = append(buf, fmt.Sprintln(suggest[item].Content))
			score = 0
			delete(suggest, item)
		}

		// Explain
		common.Log.Debug("FormatSuggest, start of sortedExplainSuggest")
		if suggest["EXP.000"].Item != "" {
			buf = append(buf, fmt.Sprintln("## ", suggest["EXP.000"].Summary))
			buf = append(buf, fmt.Sprintln(suggest["EXP.000"].Content))
			buf = append(buf, fmt.Sprint(suggest["EXP.000"].Case, "\n"))
			delete(suggest, "EXP.000")
		}
		var sortedExplainSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "EXP") {
				sortedExplainSuggest = append(sortedExplainSuggest, item)
			}
		}
		sort.Strings(sortedExplainSuggest)
		for _, item := range sortedExplainSuggest {
			buf = append(buf, fmt.Sprintln("### ", suggest[item].Summary))
			buf = append(buf, fmt.Sprintln(suggest[item].Content))
			buf = append(buf, fmt.Sprint(suggest[item].Case, "\n"))
		}

		// Profiling
		common.Log.Debug("FormatSuggest, start of sortedProfilingSuggest")
		var sortedProfilingSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "PRO") {
				sortedProfilingSuggest = append(sortedProfilingSuggest, item)
			}
		}
		sort.Strings(sortedProfilingSuggest)
		if len(sortedProfilingSuggest) > 0 {
			buf = append(buf, "## Profiling信息\n")
		}
		for _, item := range sortedProfilingSuggest {
			buf = append(buf, fmt.Sprintln(suggest[item].Content))
			delete(suggest, item)
		}

		// Trace
		common.Log.Debug("FormatSuggest, start of sortedTraceSuggest")
		var sortedTraceSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "TRA") {
				sortedTraceSuggest = append(sortedTraceSuggest, item)
			}
		}
		sort.Strings(sortedTraceSuggest)
		if len(sortedTraceSuggest) > 0 {
			buf = append(buf, "## Trace信息\n")
		}
		for _, item := range sortedTraceSuggest {
			buf = append(buf, fmt.Sprintln(suggest[item].Content))
			delete(suggest, item)
		}

		// Index
		common.Log.Debug("FormatSuggest, start of sortedIdxSuggest")
		var sortedIdxSuggest []string
		for item := range suggest {
			if strings.HasPrefix(item, "IDX") {
				sortedIdxSuggest = append(sortedIdxSuggest, item)
			}
		}
		sort.Strings(sortedIdxSuggest)
		for _, item := range sortedIdxSuggest {
			buf = append(buf, fmt.Sprintln("## ", common.MarkdownEscape(suggest[item].Summary)))
			buf = append(buf, fmt.Sprintln("* **Item:** ", item))
			buf = append(buf, fmt.Sprintln("* **Severity:** ", suggest[item].Severity))
			minus, err := strconv.Atoi(strings.Trim(suggest[item].Severity, "L"))
			if err == nil {
				score = score - minus*5
			} else {
				common.Log.Debug("FormatSuggest, sortedIdxSuggest, strconv.Atoi, Error: ", err)
				score = 0
			}
			buf = append(buf, fmt.Sprintln("* **Content:** ", common.MarkdownEscape(suggest[item].Content)))

			if format == "duplicate-key-checker" {
				buf = append(buf, fmt.Sprintf("* **原建表语句:** \n```sql\n%s\n```\n", suggest[item].Case), "\n\n")
			} else {
				buf = append(buf, fmt.Sprint("* **Case:** ", common.MarkdownEscape(suggest[item].Case), "\n\n"))
			}
		}

		// Heuristic
		common.Log.Debug("FormatSuggest, start of sortedHeuristicSuggest")
		var sortedHeuristicSuggest []string
		for item := range suggest {
			if !strings.HasPrefix(item, "EXP") &&
				!strings.HasPrefix(item, "IDX") &&
				!strings.HasPrefix(item, "PRO") {
				sortedHeuristicSuggest = append(sortedHeuristicSuggest, item)
			}
		}
		sort.Strings(sortedHeuristicSuggest)
		for _, item := range sortedHeuristicSuggest {
			buf = append(buf, fmt.Sprintln("##", suggest[item].Summary))
			if item == "OK" {
				continue
			}
			buf = append(buf, fmt.Sprintln("* **Item:** ", item))
			buf = append(buf, fmt.Sprintln("* **Severity:** ", suggest[item].Severity))
			minus, err := strconv.Atoi(strings.Trim(suggest[item].Severity, "L"))
			if err == nil {
				score = score - minus*5
			} else {
				common.Log.Debug("FormatSuggest, sortedHeuristicSuggest, strconv.Atoi, Error: ", err)
				score = 0
			}
			buf = append(buf, fmt.Sprintln("* **Content:** ", common.MarkdownEscape(suggest[item].Content)))
			// buf = append(buf, fmt.Sprint("* **Case:** ", common.MarkdownEscape(suggest[item].Case), "\n\n"))
		}

	default:
		common.Log.Debug("report-type: %s", format)
		buf = append(buf, fmt.Sprintln("Query: ", sql))
		for _, rule := range suggest {
			buf = append(buf, pretty.Sprint(rule))
		}
	}

	// 打分
	var str string
	switch common.Config.ReportType {
	case "markdown", "html":
		if len(buf) > 1 {
			str = buf[0] + "\n" + common.Score(score) + "\n\n" + strings.Join(buf[1:], "\n")
		}
	default:
		str = strings.Join(buf, "\n")
	}

	return suggest, str
}

// JSONSuggest json format suggestion
type JSONSuggest struct {
	ID             string   `json:"ID"`
	Fingerprint    string   `json:"Fingerprint"`
	Score          int      `json:"Score"`
	Sample         string   `json:"Sample"`
	Explain        []Rule   `json:"Explain"`
	HeuristicRules []Rule   `json:"HeuristicRules"`
	IndexRules     []Rule   `json:"IndexRules"`
	Tables         []string `json:"Tables"`
}

func formatJSON(sql string, db string, suggest map[string]Rule) string {
	var id, fingerprint, result string

	fingerprint = query.Fingerprint(sql)
	id = query.Id(fingerprint)

	// Score
	score := 100
	for item := range suggest {
		l, err := strconv.Atoi(strings.TrimLeft(suggest[item].Severity, "L"))
		if err != nil {
			common.Log.Error("formatJSON strconv.Atoi error: %s, item: %s, serverity: %s", err.Error(), item, suggest[item].Severity)
		}
		score = score - l*5
		// ## MySQL execute failed
		if strings.HasPrefix(item, "ERR") && suggest[item].Content != "" {
			score = 0
		}
	}
	if score < 0 {
		score = 0
	}

	sug := JSONSuggest{
		ID:          id,
		Fingerprint: fingerprint,
		Sample:      sql,
		Tables:      ast.SchemaMetaInfo(sql, db),
		Score:       score,
	}

	// Explain info
	var sortItem []string
	for item := range suggest {
		if strings.HasPrefix(item, "EXP") {
			sortItem = append(sortItem, item)
		}
	}
	sort.Strings(sortItem)
	for _, i := range sortItem {
		sug.Explain = append(sug.Explain, suggest[i])
	}
	sortItem = make([]string, 0)

	// Index advisor
	for item := range suggest {
		if strings.HasPrefix(item, "IDX") {
			sortItem = append(sortItem, item)
		}
	}
	sort.Strings(sortItem)
	for _, i := range sortItem {
		sug.IndexRules = append(sug.IndexRules, suggest[i])
	}
	sortItem = make([]string, 0)

	// Heuristic rules
	for item := range suggest {
		if !strings.HasPrefix(item, "EXP") && !strings.HasPrefix(item, "IDX") {
			if strings.HasPrefix(item, "ERR") && suggest[item].Content == "" {
				continue
			}
			sortItem = append(sortItem, item)
		}
	}
	sort.Strings(sortItem)
	for _, i := range sortItem {
		sug.HeuristicRules = append(sug.HeuristicRules, suggest[i])
	}
	sortItem = make([]string, 0)

	js, err := json.MarshalIndent(sug, "", "  ")
	if err == nil {
		result = fmt.Sprint(string(js))
	} else {
		common.Log.Error("formatJSON json.Marshal Error: %v", err)
	}
	return result
}

// ListHeuristicRules 打印支持的启发式规则，对应命令行参数-list-heuristic-rules
func ListHeuristicRules(rules ...map[string]Rule) {
	switch common.Config.ReportType {
	case "json":
		js, err := json.MarshalIndent(rules, "", "  ")
		if err == nil {
			fmt.Println(string(js))
		}
	default:
		fmt.Print("# 启发式规则建议\n\n[toc]\n\n")
		for _, r := range rules {
			delete(r, "OK")
			for _, item := range common.SortedKey(r) {
				fmt.Print("## ", common.MarkdownEscape(r[item].Summary),
					"\n\n* **Item**:", r[item].Item,
					"\n* **Severity**:", r[item].Severity,
					"\n* **Content**:", common.MarkdownEscape(r[item].Content),
					"\n* **Case**:\n\n```sql\n", r[item].Case, "\n```\n")
			}
		}
	}
}

// ListTestSQLs 打印测试用的SQL，方便测试，对应命令行参数-list-test-sqls
func ListTestSQLs() {
	for _, sql := range common.TestSQLs {
		fmt.Println(sql)
	}
}
