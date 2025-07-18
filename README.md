# Cubo Architecture V2 — Minimal C JIT Compiler

**Cubo Architecture V2** is a lightweight, high-performance, single-file Just-In-Time (JIT) compiler for a minimal subset of the C programming language. Implemented entirely in C, it provides direct machine code generation without relying on LLVM or external libraries.

---

## Features

- High-speed compilation and execution
- Direct machine code generation for `x86_64` and `aarch64` platforms
- Support for single-line (`//`) and multi-line (`/* */`) comments
- Precise token and syntax error reporting with line and column information
- Secure execution environment with memory protection and signal handling
- Minimalistic implementation with clean structure, suitable for study or extension

---

## Requirements

- C compiler (`clang` or `gcc`)
- Linux system with `x86_64` or `aarch64` architecture

---

## Building

To compile the JIT compiler:

```bash
clang -O2 -o cubo cubo.c
```

---

## Usage

To run a simple C source file:

```bash
./cubo your_file.c
echo $?
```

The return value of the compiled C function will be printed via the shell’s `$?`.

---

## Supported Syntax

Cubo supports the following subset of the C language:

```c
int main() {
    return <integer_literal>;
}
```

Valid syntax includes:

- Proper `int main()` function definition
- A single `return` statement with a signed 32-bit integer literal
- Standard C comments (`//`, `/* */`)
- Arbitrary whitespace and formatting

---

## Example

**example.c**
```c
// Example demonstrating return value
int main() {
    /* Return a test value */
    return -42;
}
```

```bash
./cubo example.c
echo $?  # Output will be (256 - 42) = 214 due to Unix return encoding
```

---

## Architecture Overview

### Lexer

- Tokenizes input source code
- Skips whitespace and comments
- Recognizes keywords: `int`, `main`, `return`
- Recognizes symbols: `(`, `)`, `{`, `}`, `;` and integer literals

### Parser

- Enforces syntax structure: `int main() { return <int>; }`
- Validates literal range (`int32_t`)
- Invokes backend code generation

### Code Generation

Generates native machine code in memory:

- On `x86_64`: Uses `mov eax, imm32` followed by `ret`
- On `aarch64`: Uses `movz`, optionally `movk`, followed by `ret`

### Execution

- Allocates memory with `mmap` and applies `PROT_EXEC`
- Sets up a signal handler for segmentation faults
- Executes the compiled code directly and returns the result

---

## Limitations

- Only supports a minimal subset of the C language
- No variables, expressions, control flow, or standard library
- Return value must be within signed 32-bit integer range
- Only `x86_64` and `aarch64` Linux platforms are supported

---

## Error Handling

Compilation errors include:

- Unexpected tokens or missing syntax elements
- Invalid or out-of-range integer literals
- Unknown or unsupported keywords or characters

All errors report the exact line and column of occurrence for clarity.

---

## License

This software is provided under the MIT License or Public Domain, at your discretion. You are free to use, modify, and distribute it with or without attribution.

---

## Contribution

Contributions are welcome under the following constraints:

- Code must remain single-file
- Compilation must remain free of external dependencies
- Maintain clarity, robustness, and safe memory handling
