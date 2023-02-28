## Download the binary installer

```bash
wget https://github.com/yassineim/soar/releases/download/${tag}/soar.${OS}-amd64 -O soar
chmod a+x soar
For example.
wget https://github.com/yassineim/soar/releases/download/0.9.0/soar.linux-amd64 -O soar
chmod a+x soar
```

## Source code installation

### Dependent software

General dependencies

* Go 1.12+
* git

Advanced dependencies (for developers only)

* [mysql](https://dev.mysql.com/doc/refman/8.0/en/mysql.html) The client version needs to be the same as the MySQL version in the container to avoid unreachable problems due to authentication
* [docker](https://docs.docker.com/engine/reference/commandline/cli/) MySQL Server test container management
* [govendor](https://github.com/kardianos/govendor) Go package management
* [retool](https://github.com/twitchtv/retool) Dependency on external code quality static checker tool binary file management

### Generate binary files

```bash
go get -d github.com/yassineim/soar
cd ${GOPATH}/src/github.com/yassineim/soar && make
```

### Development debugging

The following command can be skipped if you don't have the energy to engage in SOAR development.

* make deps dependency check
* make vitess Upgrade Vitess Parser dependency
* make tidb Upgrade TiDB Parser dependency
* make fmt code formatting, uniform style
* make lint code quality check
* make docker Start a MySQL test container that can be used to test features that depend on metadata checking or differences between versions of MySQL
* make test Run all test cases
* make cover Code test coverage check
* make doc automatically generates documentation for -list-XX on the command line.
* make daily Daily builds to keep up with Vitess, TiDB dependency changes
* make release Generate Linux, Windows, Mac releases

## Installation verification

```bash
echo 'select * from film' | ./soar
```
