# ![SOAR](https://raw.githubusercontent.com/XiaoMi/soar/master/doc/images/logo.png)

[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/xiaomi-dba/soar)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](http://github.com/XiaoMi/soar/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/XiaoMi/soar)](https://goreportcard.com/report/github.com/XiaoMi/soar)
[![Build Status](https://travis-ci.org/XiaoMi/soar.svg?branch=master)](https://travis-ci.org/XiaoMi/soar)
[![GoDoc](https://godoc.org/github.com/XiaoMi/soar?status.svg)](https://godoc.org/github.com/XiaoMi/soar)

[文档](http://github.com/XiaoMi/soar/tree/master/doc) | [FAQ](http://github.com/XiaoMi/soar/blob/master/doc/FAQ.md) | [变更记录](http://github.com/XiaoMi/soar/blob/master/CHANGES.md) | [路线图](http://github.com/XiaoMi/soar/blob/master/doc/roadmap.md) | [English](http://github.com/XiaoMi/soar/blob/master/README_EN.md)


## SOAR

SOAR (SQL Optimizer And Rewriter) is an automated tool for optimizing and rewriting SQL. It is developed and maintained by the database team of Xiaomi AI and Cloud Platform.

## Features

* Cross-platform support (Linux, Mac environments are supported, Windows environment is also supported in theory, but not fully tested)
* Currently only support MySQL syntax family protocol for SQL optimization
* Support for heuristic-based statement optimization
* Supports multi-column index optimization for complex queries (UPDATE, INSERT, DELETE, SELECT)
* Support for EXPLAIN information rich interpretation
* Support SQL fingerprinting, compression and beautification
* Support for merging multiple ALTER requests for the same table
* Support for SQL rewriting with custom rules

## Quick Start

* [Installation and Use](http://github.com/XiaoMi/soar/blob/master/doc/install.md)
* [Architecture](http://github.com/XiaoMi/soar/blob/master/doc/structure.md)
* [Configuration Files](http://github.com/XiaoMi/soar/blob/master/doc/config.md)
* [Common Commands](http://github.com/XiaoMi/soar/blob/master/doc/cheatsheet.md)
* [Product Comparison](http://github.com/XiaoMi/soar/blob/master/doc/comparison.md)
* [Roadmap](http://github.com/XiaoMi/soar/blob/master/doc/roadmap.md)

## Communication and Feedback

* Welcome to submit issue reports and suggestions via Github Issues
* QQ Group: 779359816 (not full) 758940447 (full)
* [Gitter](https://gitter.im/xiaomi-dba/soar) Recommended

Translated with www.DeepL.com/Translator (free version)
