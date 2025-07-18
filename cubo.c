// CUBO ARCHITECTURE V2 (Single-file, No LLVM, Ultra-Fast, Optimized)
// A minimal C JIT compiler implemented in C.
// V2: Added support for // and /* */ comments. Optimized keyword matching. Fixed negative numbers.
// To compile: clang -O2 -o cubo cubo.c
// To run: ./cubo your_file.c; echo $?

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>

// ────────────────────────────────────────────────────────────────────────────
//  Data Structures & Forward Declarations
// ────────────────────────────────────────────────────────────────────────────

typedef enum {
T_INT, T_MAIN, T_LPAREN, T_RPAREN, T_LBRACE, T_RBRACE,
T_RETURN, T_SEMICOLON, T_INTEGER_LITERAL, T_EOF, T_UNKNOWN
// Add more tokens here for future expansion
} TokenType;

typedef struct {
TokenType type;
const char *start;
int length;
int line;
int col;
} Token;

typedef struct {
const char *source;
const char *cursor;
int line;
int col;
Token current_token;
uint8_t *code_buf;
size_t code_size;
size_t code_capacity;
} Compiler;

void fail(const char *fmt, ...);
void fail_at(int line, int col, const char *fmt, ...);

// ────────────────────────────────────────────────────────────────────────────
//  1. Frontend: Lexer (Enhanced & Optimized)
// ────────────────────────────────────────────────────────────────────────────

void advance(Compiler *c) {
if (*c->cursor == '\n') {
c->line++;
c->col = 1;
} else {
c->col++;
}
c->cursor++;
}

char peek(Compiler *c) { return *c->cursor; }
char peek_next(Compiler *c) { return c->cursor[1]; }
int is_at_end(Compiler *c) { return *c->cursor == '\0'; }

void skip_whitespace_and_comments(Compiler c) {
for (;;) {
char ch = peek(c);
switch (ch) {
case ' ':
case '\r':
case '\t':
case '\n':
advance(c);
break;
case '/':
if (peek_next(c) == '/') { // Single-line comment
while (peek(c) != '\n' && !is_at_end(c)) advance(c);
} else if (peek_next(c) == '') { // Multi-line comment
advance(c); // consume '/'
advance(c); // consume ''
while (!(peek(c) == '' && peek_next(c) == '/') && !is_at_end(c)) {
advance(c);
}
if (!is_at_end(c)) advance(c); // consume '*'
if (!is_at_end(c)) advance(c); // consume '/'
} else {
return; // It's a division operator, not a comment
}
break;
default:
return;
}
}
}

Token make_token(Compiler *c, TokenType type, const char start, int length) {
Token token;
token.type = type;
token.start = start;
token.length = length;
token.line = c->line;
// Calculate the token's starting column correctly
const char temp_cursor = c->cursor - length;
int temp_col = c->col - length;
while(temp_cursor > c->source && *(temp_cursor-1) != '\n') {
temp_cursor--;
temp_col--;
}
token.col = temp_col < 1 ? 1 : temp_col;
return token;
}

Token identifier(Compiler *c) {
const char *start = c->cursor;
while (isalnum(peek(c)) || peek(c) == '_') advance(c);
int length = c->cursor - start;

// Optimized keyword matching  
switch (*start) {  
    case 'i': if (length == 3 && strncmp(start + 1, "nt", 2) == 0) return make_token(c, T_INT, start, length); break;  
    case 'm': if (length == 4 && strncmp(start + 1, "ain", 3) == 0) return make_token(c, T_MAIN, start, length); break;  
    case 'r': if (length == 6 && strncmp(start + 1, "eturn", 5) == 0) return make_token(c, T_RETURN, start, length); break;  
}  

return make_token(c, T_UNKNOWN, start, length);

}

Token number(Compiler *c) {
const char *start = c->cursor;
if (peek(c) == '-') advance(c); // Accept leading minus
while (isdigit(peek(c))) advance(c);
return make_token(c, T_INTEGER_LITERAL, start, c->cursor - start);
}

Token get_next_token(Compiler *c) {
skip_whitespace_and_comments(c);
const char *start = c->cursor;

if (is_at_end(c)) return make_token(c, T_EOF, start, 0);  

char ch = peek(c);  
if (isalpha(ch) || ch == '_') return identifier(c);  
if (isdigit(ch) || (ch == '-' && isdigit(peek_next(c)))) return number(c);  

advance(c);  
switch (ch) {  
    case '(': return make_token(c, T_LPAREN, start, 1);  
    case ')': return make_token(c, T_RPAREN, start, 1);  
    case '{': return make_token(c, T_LBRACE, start, 1);  
    case '}': return make_token(c, T_RBRACE, start, 1);  
    case ';': return make_token(c, T_SEMICOLON, start, 1);  
}  

Token unknown = make_token(c, T_UNKNOWN, start, 1);  
fail_at(unknown.line, unknown.col, "unknown character '%.*s'", unknown.length, unknown.start);  
return unknown; // Unreachable

}

// ────────────────────────────────────────────────────────────────────────────
//  2. Parser (with Integrated Semantic Checks & Codegen calls)
// ────────────────────────────────────────────────────────────────────────────

const char* token_name(TokenType type) {
switch (type) {
case T_INT: return "'int'"; case T_MAIN: return "'main'"; case T_LPAREN: return "'('";
case T_RPAREN: return "')'"; case T_LBRACE: return "'{'"; case T_RBRACE: return "'}'";
case T_RETURN: return "'return'"; case T_SEMICOLON: return "';'"; case T_INTEGER_LITERAL: return "integer literal";
case T_EOF: return "end of file"; default: return "unknown token";
}
}

void consume(Compiler *c, TokenType type, const char *message) {
if (c->current_token.type == type) {
c->current_token = get_next_token(c);
return;
}
char found_val[32];
snprintf(found_val, sizeof(found_val), "'%.*s'", c->current_token.length, c->current_token.start);
if (message) {
fail_at(c->current_token.line, c->current_token.col, "%s", message);
} else {
fail_at(c->current_token.line, c->current_token.col, "expected %s but found %s", token_name(type), found_val);
}
}

// Forward declaration
void generate_code(Compiler *c, int32_t value);

void parse_and_compile(Compiler *c) {
c->current_token = get_next_token(c);

if (c->current_token.type == T_UNKNOWN) {  
    fail_at(c->current_token.line, c->current_token.col, "unknown keyword '%.*s'", c->current_token.length, c->current_token.start);  
}  

consume(c, T_INT, NULL);  
consume(c, T_MAIN, NULL);  
consume(c, T_LPAREN, NULL);  
consume(c, T_RPAREN, NULL);  
consume(c, T_LBRACE, NULL);  
consume(c, T_RETURN, NULL);  

Token literal_token = c->current_token;  
consume(c, T_INTEGER_LITERAL, "expected integer literal after 'return'");  
  
char *end;  
long long value = strtoll(literal_token.start, &end, 10);  
if (value > INT_MAX || value < INT_MIN) {  
    fail_at(literal_token.line, literal_token.col, "literal %.*s out of 32-bit range", literal_token.length, literal_token.start);  
}  

generate_code(c, (int32_t)value);  

consume(c, T_SEMICOLON, "expected ';' after return value");  
consume(c, T_RBRACE, NULL);  
consume(c, T_EOF, "unexpected tokens after function body");

}

// ────────────────────────────────────────────────────────────────────────────
//  3. Backend: Direct Code Generator
// ────────────────────────────────────────────────────────────────────────────

void emit_byte(Compiler *c, uint8_t byte) {
if (c->code_size >= c->code_capacity) {
c->code_capacity = c->code_capacity < 8 ? 8 : c->code_capacity * 2;
c->code_buf = realloc(c->code_buf, c->code_capacity);
if (!c->code_buf) fail("Failed to reallocate memory for code buffer");
}
c->code_buf[c->code_size++] = byte;
}

void emit_bytes(Compiler c, void data, size_t count) {
for (size_t i = 0; i < count; i++) {
emit_byte(c, ((uint8_t*)data)[i]);
}
}

void generate_code(Compiler *c, int32_t value) {
#if defined(x86_64) || defined(_M_X64)
emit_byte(c, 0xb8); // mov eax, imm32
emit_bytes(c, &value, 4);
emit_byte(c, 0xc3); // ret
#elif defined(aarch64) || defined(_M_ARM64)
uint32_t u_value = (uint32_t)value;
uint16_t low16 = u_value & 0xFFFF;
uint16_t high16 = (u_value >> 16) & 0xFFFF;
uint32_t movz = 0x52800000 | ((uint32_t)low16 << 5);
emit_bytes(c, &movz, 4);
if (high16 != 0) {
uint32_t movk = 0x72a00000 | ((uint32_t)high16 << 5);
emit_bytes(c, &movk, 4);
}
uint32_t ret = 0xd65f03c0;
emit_bytes(c, &ret, 4);
#else
#error "Unsupported architecture for JIT compilation"
#endif
}

// ────────────────────────────────────────────────────────────────────────────
//  4. & 5. Execution Buffer, Execution, and System Interface
// ────────────────────────────────────────────────────────────────────────────

void segv_handler(int sig) {
fprintf(stderr, "Runtime error: segmentation fault in user code\n");
_exit(139);
}

int execute_code(Compiler *c) {
if (c->code_size == 0) fail("No code generated.");

void *mem = mmap(NULL, c->code_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);  
if (mem == MAP_FAILED) fail("mmap failed: [%d] %s", errno, strerror(errno));  
  
memcpy(mem, c->code_buf, c->code_size);  

if (mprotect(mem, c->code_size, PROT_READ | PROT_EXEC) == -1) {  
    munmap(mem, c->code_size);  
    fail("mprotect failed: PROT_EXEC not allowed. Reason: [%d] %s", errno, strerror(errno));  
}  

struct sigaction sa_new = {.sa_handler = segv_handler};  
struct sigaction sa_old;  
sigemptyset(&sa_new.sa_mask);  
sigaction(SIGSEGV, &sa_new, &sa_old);  

int (*jit_func)() = mem;  
int result = jit_func();  

sigaction(SIGSEGV, &sa_old, NULL);  
munmap(mem, c->code_size);  
return result;

}

char* read_file(const char* path) {
FILE *file = fopen(path, "rb");
if (!file) fail("Could not open file '%s'", path);
fseek(file, 0, SEEK_END);
long length = ftell(file);
fseek(file, 0, SEEK_SET);
char *buffer = malloc(length + 1);
if (!buffer) fail("Could not allocate memory to read file '%s'", path);
if (fread(buffer, 1, length, file) != (size_t)length) fail("Could not read entire file '%s'", path);
buffer[length] = '\0';
fclose(file);
return buffer;
}

void fail(const char *fmt, ...) {
fprintf(stderr, "Error: ");
va_list args;
va_start(args, fmt);
vfprintf(stderr, fmt, args);
va_end(args);
fprintf(stderr, "\n");
exit(1);
}

void fail_at(int line, int col, const char *fmt, ...) {
fprintf(stderr, "Error at line %d, col %d: ", line, col);
va_list args;
va_start(args, fmt);
vfprintf(stderr, fmt, args);
va_end(args);
fprintf(stderr, "\n");
exit(1);
}

int main(int argc, char **argv) {
if (argc != 2) {
fprintf(stderr, "Usage: %s <source_file.c>\n", argv[0]);
return 1;
}

Compiler compiler = {0};  
compiler.source = read_file(argv[1]);  
compiler.cursor = compiler.source;  
compiler.line = 1;  
compiler.col = 1;  
  
// Pre-allocate a reasonable buffer to avoid frequent reallocs  
compiler.code_capacity = 64;  
compiler.code_buf = malloc(compiler.code_capacity);  
if (!compiler.code_buf) fail("Failed to allocate initial code buffer");  

parse_and_compile(&compiler);  
int exit_code = execute_code(&compiler);  

free((void*)compiler.source);  
free(compiler.code_buf);  

return exit_code;

}

