Teo Schema Parser
=================

Schema parser for Teo schema language

## Roadmap

### 0.0.58 (Released on Nov 7th, 2023)

* Separate from the main project
* Rewrite and overhaul
* Schema dumps
* Code diagnostics
* Jump to definition
* Auto completion

### 0.0.59 (Released on Nov 30th, 2023)

* File format
* Trigger auto completions by `"."`, `":"` and `"$"`
* Auto completion for enum variant literals
* Jump to definition for enum variant literals
* Convert struct objects to primitive types
* Improved callable variant matching mechanics
* Object literal syntax
* Declare enum in type
* Declare object in type

### 0.0.60 (Released on Dec 17th, 2023)

* Rewrite syntax highlight with yaml and precise rules

### 0.1.0 (Currently Developing)

* Improve stability
* Optimizations
* Improve performance
* Accept indentation settings argument in format

### 0.2.0
* Add `linter` config declaration
* Separate `fix` command and `format` command
* Expand auto completion candidates for callables into snippets
* Choose completion item from callable variants
* Add `import "..." use namespace.{identifier1, identifier2 as alias2}` syntax
* Add `use namespace.{identifier1, identifier2 as alias2}` syntax

### 0.3.0

* Refactor variable names in place

### 0.4.0

* diagnostic code

### 1.0.0

* format lines in a file
* file format arguments
