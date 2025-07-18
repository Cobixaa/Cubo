// CUBO ARCHITECTURE V3 (Multi-Stage, Optimizing JIT)
// A more advanced JIT compiler for a C subset supporting variables,
// expressions, and control flow.
//
// To Compile:
//   clang -O2 -o cubo cubo.c
//
// To Run:
//   ./cubo -c0 your_file.c   (No optimizations)
//   ./cubo -c1 your_file.c   (With Constant Folding optimization)
//   echo $?                  (To see the result)
//

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>

#define MAX_LOCALS 256
#define MAX_CODE_SIZE 65536
#define MAX_JUMPS 256

// ────────────────────────────────────────────────────────────────────────────
//  ARCHITECTURE OVERVIEW
//
//  1. Lexer -> [Tokens]
//     Scans the source code and produces a stream of tokens.
//
//  2. Parser -> [AST - Abstract Syntax Tree]
//     Consumes tokens and builds a tree representing the code's structure.
//     Example: `x = 5 + 10` becomes an assignment node with a variable node
//     'x' and an addition node with children '5' and '10'.
//
//  3. Optimizer -> [Optimized AST]
//     (Optional, controlled by -c1)
//     Walks the AST and performs simplifications.
//     Example: The addition node with '5' and '10' is replaced by a single
//     number node '15'. This is "Constant Folding".
//
//  4. Bytecode Emitter -> [Bytecode]
//     Walks the final AST and generates a simple, linear, stack-based
//     intermediate representation (IR).
//     Example: `PUSH 15; STORE_VAR 'x'`.
//
//  5. JIT Backend -> [x86_64 Machine Code]
//     Translates the bytecode into native machine code in an executable buffer.
//     Manages registers and the machine stack.
//
//  6. Execution -> [Result]
//     The buffer is executed, and the final result is returned.
//
// ────────────────────────────────────────────────────────────────────────────

// Forward Declarations
typedef struct Compiler Compiler;
typedef struct ASTNode ASTNode;
void fail(const char *fmt, ...);
void fail_at(int line, int col, const char *fmt, ...);

// ────────────────────────────────────────────────────────────────────────────
//  1. Lexer & Tokenizer
// ────────────────────────────────────────────────────────────────────────────
typedef enum {
    T_EOF, T_UNKNOWN,
    // Keywords
    T_INT, T_RETURN, T_IF, T_ELSE,
    // Literals
    T_IDENTIFIER, T_INTEGER_LITERAL,
    // Operators
    T_PLUS, T_MINUS, T_STAR, T_SLASH, T_EQ, T_EQ_EQ, T_NOT_EQ,
    // Punctuation
    T_LPAREN, T_RPAREN, T_LBRACE, T_RBRACE, T_SEMICOLON,
} TokenType;

typedef struct { TokenType type; const char *start; int length; int line; int col; } Token;

// Lexer implementation is straightforward and omitted for brevity, assuming a robust one exists
// from the previous version. The full implementation is at the end of the file.

// ────────────────────────────────────────────────────────────────────────────
//  2. Abstract Syntax Tree (AST)
// ────────────────────────────────────────────────────────────────────────────
typedef enum {
    NODE_NUMBER, NODE_VAR, NODE_UNARY, NODE_BINARY,
    NODE_ASSIGN, NODE_VAR_DECL, NODE_RETURN, NODE_IF,
    NODE_BLOCK,
} NodeType;

struct ASTNode {
    NodeType type;
    ASTNode *next; // For lists of statements
    Token token;   // For error reporting and values
    // Children
    ASTNode *left;
    ASTNode *right;
    // For IF nodes
    ASTNode *condition;
    ASTNode *then_branch;
    ASTNode *else_branch;
    // For BLOCK nodes
    ASTNode *statements;
    // For VAR_DECL/VAR nodes
    int var_index;
};

// ────────────────────────────────────────────────────────────────────────────
//  3. Bytecode Intermediate Representation
// ────────────────────────────────────────────────────────────────────────────
typedef enum {
    OP_NOP, OP_PUSH, OP_POP,
    OP_ADD, OP_SUB, OP_MUL, OP_DIV,
    OP_EQ, OP_NEQ,
    OP_STORE_VAR, OP_LOAD_VAR,
    OP_JUMP, OP_JUMP_IF_FALSE,
    OP_RETURN,
} OpCode;

// ────────────────────────────────────────────────────────────────────────────
//  Core Compiler State
// ────────────────────────────────────────────────────────────────────────────
typedef struct { const char* name; int stack_offset; } LocalVar;

struct Compiler {
    // Input & Lexer
    const char *source;
    const char *cursor;
    int line;
    int col;
    Token current_token;
    Token prev_token;

    // AST
    ASTNode *ast_root;

    // Symbol Table (for variables)
    LocalVar locals[MAX_LOCALS];
    int local_count;
    int stack_top;

    // Bytecode
    uint8_t code[MAX_CODE_SIZE];
    int32_t code_operands[MAX_CODE_SIZE];
    int code_count;

    // JIT Backend
    uint8_t *jit_buf;
    size_t jit_size;
    // For backpatching jumps
    int jump_patch_locs[MAX_JUMPS];
    int jump_patch_targets[MAX_JUMPS];
    int jump_patch_count;

    // Options
    int optimization_level;
};

// All function implementations are at the end to keep this top section clean.
void init_compiler(Compiler* c, const char* source, int opt_level);
void compile(Compiler* c);
int execute(Compiler* c);


// ────────────────────────────────────────────────────────────────────────────
//  Main Driver
// ────────────────────────────────────────────────────────────────────────────
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-c0 | -c1] <source_file.c>\n", argv[0]);
        fprintf(stderr, "  -c0: No optimizations (default)\n");
        fprintf(stderr, "  -c1: Enable constant-folding optimization\n");
        return 1;
    }

    int opt_level = 0;
    const char *filepath = NULL;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-c0") == 0) {
            opt_level = 0;
        } else if (strcmp(argv[i], "-c1") == 0) {
            opt_level = 1;
        } else if (!filepath) {
            filepath = argv[i];
        } else {
            fail("Too many file arguments.");
        }
    }

    if (!filepath) fail("No source file provided.");

    FILE *file = fopen(filepath, "rb");
    if (!file) fail("Could not open file '%s'", filepath);
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *source = malloc(length + 1);
    if (!source || fread(source, 1, length, file) != (size_t)length) {
        fail("Could not read file '%s'", filepath);
    }
    source[length] = '\0';
    fclose(file);

    Compiler compiler;
    init_compiler(&compiler, source, opt_level);

    compile(&compiler);
    int exit_code = execute(&compiler);

    free(source);
    return exit_code;
}


// ┌──────────────────────────────────────────────────────────────────────────┐
// │                  FULL IMPLEMENTATION DETAILS BELOW                       │
// └──────────────────────────────────────────────────────────────────────────┘

// Utility Functions
void fail(const char *fmt, ...) {
    fprintf(stderr, "Error: ");
    va_list args; va_start(args, fmt); vfprintf(stderr, fmt, args); va_end(args);
    fprintf(stderr, "\n"); exit(1);
}
void fail_at(int line, int col, const char *fmt, ...) {
    fprintf(stderr, "Error at line %d, col %d: ", line, col);
    va_list args; va_start(args, fmt); vfprintf(stderr, fmt, args); va_end(args);
    fprintf(stderr, "\n"); exit(1);
}

// ======================= LEXER =======================
void advance_lexer(Compiler* c) {
    if (*c->cursor == '\n') { c->line++; c->col = 1; } else { c->col++; }
    c->cursor++;
}

Token make_token(Compiler* c, TokenType type, const char* start, int length) {
    return (Token){type, start, length, c->line, c->col - length};
}

Token identifier_or_keyword(Compiler* c) {
    const char *start = c->cursor;
    while (isalnum(*c->cursor) || *c->cursor == '_') advance_lexer(c);
    int len = c->cursor - start;
    #define KEYWORD(s, t) if (len == strlen(s) && strncmp(start, s, len) == 0) return make_token(c, t, start, len)
    KEYWORD("int", T_INT); KEYWORD("return", T_RETURN);
    KEYWORD("if", T_IF); KEYWORD("else", T_ELSE);
    #undef KEYWORD
    return make_token(c, T_IDENTIFIER, start, len);
}

Token number(Compiler* c) {
    const char *start = c->cursor;
    while (isdigit(*c->cursor)) advance_lexer(c);
    return make_token(c, T_INTEGER_LITERAL, start, c->cursor - start);
}

void get_next_token(Compiler* c) {
    c->prev_token = c->current_token;
    while (isspace(*c->cursor)) advance_lexer(c);
    if (*c->cursor == '\0') { c->current_token = make_token(c, T_EOF, c->cursor, 0); return; }
    if (isalpha(*c->cursor) || *c->cursor == '_') { c->current_token = identifier_or_keyword(c); return; }
    if (isdigit(*c->cursor)) { c->current_token = number(c); return; }
    const char* start = c->cursor; advance_lexer(c);
    switch (*start) {
        case '+': c->current_token = make_token(c, T_PLUS, start, 1); return;
        case '-': c->current_token = make_token(c, T_MINUS, start, 1); return;
        case '*': c->current_token = make_token(c, T_STAR, start, 1); return;
        case '/': c->current_token = make_token(c, T_SLASH, start, 1); return;
        case '(': c->current_token = make_token(c, T_LPAREN, start, 1); return;
        case ')': c->current_token = make_token(c, T_RPAREN, start, 1); return;
        case '{': c->current_token = make_token(c, T_LBRACE, start, 1); return;
        case '}': c->current_token = make_token(c, T_RBRACE, start, 1); return;
        case ';': c->current_token = make_token(c, T_SEMICOLON, start, 1); return;
        case '=': c->current_token = make_token(c, *c->cursor == '=' ? (advance_lexer(c), T_EQ_EQ) : T_EQ, start, c->cursor-start); return;
        case '!': c->current_token = make_token(c, *c->cursor == '=' ? (advance_lexer(c), T_NOT_EQ) : T_UNKNOWN, start, c->cursor-start); return;
    }
    c->current_token = make_token(c, T_UNKNOWN, start, 1);
}

void consume(Compiler* c, TokenType type, const char* msg) {
    if (c->current_token.type == type) { get_next_token(c); return; }
    fail_at(c->current_token.line, c->current_token.col, "%s", msg);
}

// ======================= PARSER (Builds AST) =======================
ASTNode* new_ast_node(NodeType type, Token token) {
    ASTNode* node = calloc(1, sizeof(ASTNode));
    if (!node) fail("Memory allocation failed for AST node.");
    node->type = type; node->token = token;
    return node;
}

ASTNode* parse_expression(Compiler* c);
ASTNode* parse_statement(Compiler* c);

ASTNode* parse_primary(Compiler* c) {
    if (c->current_token.type == T_INTEGER_LITERAL) {
        ASTNode* n = new_ast_node(NODE_NUMBER, c->current_token); get_next_token(c); return n;
    }
    if (c->current_token.type == T_IDENTIFIER) {
        ASTNode* n = new_ast_node(NODE_VAR, c->current_token); get_next_token(c); return n;
    }
    if (c->current_token.type == T_LPAREN) {
        get_next_token(c); ASTNode* n = parse_expression(c);
        consume(c, T_RPAREN, "Expected ')' after expression."); return n;
    }
    fail_at(c->current_token.line, c->current_token.col, "Unexpected token in expression.");
    return NULL;
}

ASTNode* parse_term(Compiler* c) {
    ASTNode* node = parse_primary(c);
    while (c->current_token.type == T_STAR || c->current_token.type == T_SLASH) {
        Token op = c->current_token; get_next_token(c);
        ASTNode* right = parse_primary(c);
        ASTNode* binary_node = new_ast_node(NODE_BINARY, op);
        binary_node->left = node; binary_node->right = right; node = binary_node;
    }
    return node;
}
ASTNode* parse_addition(Compiler* c) {
    ASTNode* node = parse_term(c);
    while (c->current_token.type == T_PLUS || c->current_token.type == T_MINUS) {
        Token op = c->current_token; get_next_token(c);
        ASTNode* right = parse_term(c);
        ASTNode* binary_node = new_ast_node(NODE_BINARY, op);
        binary_node->left = node; binary_node->right = right; node = binary_node;
    }
    return node;
}
ASTNode* parse_comparison(Compiler* c) {
    ASTNode* node = parse_addition(c);
    if (c->current_token.type == T_EQ_EQ || c->current_token.type == T_NOT_EQ) {
        Token op = c->current_token; get_next_token(c);
        ASTNode* right = parse_addition(c);
        ASTNode* binary_node = new_ast_node(NODE_BINARY, op);
        binary_node->left = node; binary_node->right = right; node = binary_node;
    }
    return node;
}
ASTNode* parse_assignment(Compiler* c) {
    ASTNode* left = parse_comparison(c);
    if (c->current_token.type == T_EQ) {
        if (left->type != NODE_VAR) fail_at(left->token.line, left->token.col, "Invalid assignment target.");
        Token op = c->current_token; get_next_token(c);
        ASTNode* right = parse_assignment(c);
        ASTNode* assign_node = new_ast_node(NODE_ASSIGN, op);
        assign_node->left = left; assign_node->right = right; return assign_node;
    }
    return left;
}
ASTNode* parse_expression(Compiler* c) { return parse_assignment(c); }

ASTNode* parse_block(Compiler* c) {
    Token brace = c->current_token;
    consume(c, T_LBRACE, "Expected '{' to start a block.");
    ASTNode* head = NULL, *tail = NULL;
    while (c->current_token.type != T_RBRACE && c->current_token.type != T_EOF) {
        ASTNode* stmt = parse_statement(c);
        if (!head) head = tail = stmt; else { tail->next = stmt; tail = stmt; }
    }
    consume(c, T_RBRACE, "Expected '}' to end a block.");
    ASTNode* block_node = new_ast_node(NODE_BLOCK, brace);
    block_node->statements = head;
    return block_node;
}

ASTNode* parse_statement(Compiler* c) {
    Token T = c->current_token;
    if (T.type == T_RETURN) {
        get_next_token(c); ASTNode* n = new_ast_node(NODE_RETURN, T);
        n->left = parse_expression(c); consume(c, T_SEMICOLON, "Expected ';' after return statement."); return n;
    }
    if (T.type == T_INT) {
        get_next_token(c); Token id = c->current_token; consume(c, T_IDENTIFIER, "Expected identifier after 'int'.");
        ASTNode* decl = new_ast_node(NODE_VAR_DECL, id);
        if (c->current_token.type == T_EQ) {
            get_next_token(c); ASTNode* assign = new_ast_node(NODE_ASSIGN, c->prev_token);
            assign->left = new_ast_node(NODE_VAR, id); assign->right = parse_expression(c);
            decl->left = assign;
        }
        consume(c, T_SEMICOLON, "Expected ';' after variable declaration."); return decl;
    }
    if (T.type == T_IF) {
        get_next_token(c); consume(c, T_LPAREN, "Expected '(' after 'if'.");
        ASTNode* n = new_ast_node(NODE_IF, T);
        n->condition = parse_expression(c); consume(c, T_RPAREN, "Expected ')' after if condition.");
        n->then_branch = parse_statement(c);
        if (c->current_token.type == T_ELSE) { get_next_token(c); n->else_branch = parse_statement(c); }
        return n;
    }
    if (T.type == T_LBRACE) return parse_block(c);

    ASTNode* expr = parse_expression(c); consume(c, T_SEMICOLON, "Expected ';' after expression statement."); return expr;
}

// ======================= OPTIMIZER =======================
int eval_ast(ASTNode* node, int* result) {
    if (node->type == NODE_NUMBER) {
        *result = strtol(node->token.start, NULL, 10); return 1;
    }
    if (node->type == NODE_BINARY) {
        int left_val, right_val;
        if (eval_ast(node->left, &left_val) && eval_ast(node->right, &right_val)) {
            switch (node->token.type) {
                case T_PLUS:  *result = left_val + right_val; return 1;
                case T_MINUS: *result = left_val - right_val; return 1;
                case T_STAR:  *result = left_val * right_val; return 1;
                case T_SLASH: *result = right_val != 0 ? left_val / right_val : 0; return 1;
                default: break;
            }
        }
    }
    return 0;
}

void optimize_ast(Compiler* c, ASTNode* node) {
    if (!node) return;
    optimize_ast(c, node->left); optimize_ast(c, node->right);
    optimize_ast(c, node->condition); optimize_ast(c, node->then_branch);
    optimize_ast(c, node->else_branch); optimize_ast(c, node->statements);
    optimize_ast(c, node->next);

    if (c->optimization_level >= 1 && node->type == NODE_BINARY) {
        int result;
        if (eval_ast(node, &result)) {
            char buf[32]; snprintf(buf, 32, "%d", result);
            node->type = NODE_NUMBER;
            node->token.start = strdup(buf); // Memory leak! For demo only.
        }
    }
}

// ======================= BYTECODE EMITTER =======================
void emit_op(Compiler* c, OpCode op, int32_t operand) {
    c->code[c->code_count] = op;
    c->code_operands[c->code_count] = operand;
    c->code_count++;
}

int add_local(Compiler* c, Token name) {
    for (int i=0; i < c->local_count; ++i) {
        if (name.length == strlen(c->locals[i].name) && strncmp(name.start, c->locals[i].name, name.length) == 0)
            fail_at(name.line, name.col, "Variable '%.*s' already declared.", name.length, name.start);
    }
    c->locals[c->local_count].name = strndup(name.start, name.length);
    c->stack_top += 8;
    c->locals[c->local_count].stack_offset = c->stack_top;
    return c->local_count++;
}

int find_local(Compiler* c, Token name) {
    for (int i=c->local_count-1; i >= 0; --i) {
        if (name.length == strlen(c->locals[i].name) && strncmp(name.start, c->locals[i].name, name.length) == 0)
            return i;
    }
    fail_at(name.line, name.col, "Undeclared variable '%.*s'.", name.length, name.start);
    return -1;
}

void emit_bytecode_from_ast(Compiler* c, ASTNode* node) {
    if (!node) return;
    switch (node->type) {
        case NODE_NUMBER: emit_op(c, OP_PUSH, strtol(node->token.start, NULL, 10)); break;
        case NODE_VAR_DECL:
            node->var_index = add_local(c, node->token);
            if (node->left) emit_bytecode_from_ast(c, node->left); // Handle declaration with assignment
            break;
        case NODE_VAR: node->var_index = find_local(c, node->token); emit_op(c, OP_LOAD_VAR, node->var_index); break;
        case NODE_ASSIGN:
            if (node->left->type != NODE_VAR) fail_at(node->token.line, node->token.col, "Invalid assignment target.");
            node->left->var_index = find_local(c, node->left->token);
            emit_bytecode_from_ast(c, node->right);
            emit_op(c, OP_STORE_VAR, node->left->var_index);
            break;
        case NODE_BINARY:
            emit_bytecode_from_ast(c, node->left);
            emit_bytecode_from_ast(c, node->right);
            if (node->token.type == T_PLUS) emit_op(c, OP_ADD, 0);
            else if (node->token.type == T_MINUS) emit_op(c, OP_SUB, 0);
            else if (node->token.type == T_STAR) emit_op(c, OP_MUL, 0);
            else if (node->token.type == T_SLASH) emit_op(c, OP_DIV, 0);
            else if (node->token.type == T_EQ_EQ) emit_op(c, OP_EQ, 0);
            else if (node->token.type == T_NOT_EQ) emit_op(c, OP_NEQ, 0);
            break;
        case NODE_RETURN: emit_bytecode_from_ast(c, node->left); emit_op(c, OP_RETURN, 0); break;
        case NODE_BLOCK: {
            ASTNode* s = node->statements;
            while(s) { emit_bytecode_from_ast(c, s); s = s->next; }
            break;
        }
        case NODE_IF: {
            emit_bytecode_from_ast(c, node->condition);
            int else_jump = c->code_count; emit_op(c, OP_JUMP_IF_FALSE, 0); // Placeholder
            emit_bytecode_from_ast(c, node->then_branch);
            if (node->else_branch) {
                int exit_jump = c->code_count; emit_op(c, OP_JUMP, 0); // Placeholder
                c->code_operands[else_jump] = c->code_count; // Patch else jump
                emit_bytecode_from_ast(c, node->else_branch);
                c->code_operands[exit_jump] = c->code_count; // Patch exit jump
            } else {
                c->code_operands[else_jump] = c->code_count; // Patch else jump
            }
            break;
        }
        default: emit_bytecode_from_ast(c, node->left);
    }
    if (node->type < NODE_RETURN) emit_bytecode_from_ast(c, node->next);
}

// ======================= JIT BACKEND (x86-64) =======================
#if defined(__x86_64__)
void emit_jit(Compiler* c, uint8_t* data, size_t size) {
    memcpy(c->jit_buf + c->jit_size, data, size); c->jit_size += size;
}
void jit_compile(Compiler* c) {
    // Prologue: set up stack frame
    emit_jit(c, (uint8_t[]){0x55}, 1); // push rbp
    emit_jit(c, (uint8_t[]){0x48, 0x89, 0xe5}, 3); // mov rbp, rsp
    uint8_t sub_rsp[] = {0x48, 0x81, 0xec, 0x00, 0x00, 0x00, 0x00}; // sub rsp, <stack_size>
    *(uint32_t*)(sub_rsp + 3) = c->stack_top;
    emit_jit(c, sub_rsp, sizeof(sub_rsp));

    for (int i=0; i<c->code_count; ++i) {
        OpCode op = c->code[i]; int32_t operand = c->code_operands[i];
        
        // Backpatch jumps if this is a target
        for (int j=0; j<c->jump_patch_count; ++j) {
            if (c->jump_patch_targets[j] == i) {
                int32_t offset = c->jit_size - (c->jump_patch_locs[j] + 4);
                *(int32_t*)(c->jit_buf + c->jump_patch_locs[j]) = offset;
            }
        }
        
        switch(op) {
            case OP_PUSH: {
                uint8_t push_imm[] = {0x68, 0x00, 0x00, 0x00, 0x00}; // push imm32
                *(uint32_t*)(push_imm + 1) = operand;
                emit_jit(c, push_imm, sizeof(push_imm));
                break;
            }
            case OP_POP: emit_jit(c, (uint8_t[]){0x58}, 1); break; // pop rax
            #define BIN_OP(add, sub, mul, div) \
                emit_jit(c, (uint8_t[]){0x5b}, 1); /* pop rbx */ \
                emit_jit(c, (uint8_t[]){0x58}, 1); /* pop rax */ \
                if(op == OP_ADD) emit_jit(c, (uint8_t[])add, 3); \
                if(op == OP_SUB) emit_jit(c, (uint8_t[])sub, 3); \
                if(op == OP_MUL) { emit_jit(c, (uint8_t[])mul, 3); } \
                if(op == OP_DIV) { emit_jit(c, (uint8_t[]){0x99}, 1); emit_jit(c, (uint8_t[])div, 3); } \
                emit_jit(c, (uint8_t[]){0x50}, 1); /* push rax */
            case OP_ADD: case OP_SUB: case OP_MUL: case OP_DIV:
                BIN_OP({0x48, 0x01, 0xd8}, {0x48, 0x29, 0xd8}, {0x48, 0x0f, 0xaf, 0xc3}, {0x48, 0xf7, 0xfb}); break;
            #define CMP_OP(opcode) \
                emit_jit(c, (uint8_t[]){0x5b}, 1); /* pop rbx */ \
                emit_jit(c, (uint8_t[]){0x58}, 1); /* pop rax */ \
                emit_jit(c, (uint8_t[]){0x48, 0x39, 0xd8}, 3); /* cmp rax, rbx */ \
                emit_jit(c, (uint8_t[]){0x0f, opcode, 0xc0}, 3); /* setcc al */ \
                emit_jit(c, (uint8_t[]){0x48, 0x0f, 0xb6, 0xc0}, 4); /* movzx rax, al */ \
                emit_jit(c, (uint8_t[]){0x50}, 1); /* push rax */
            case OP_EQ: CMP_OP(0x94); break;
            case OP_NEQ: CMP_OP(0x95); break;
            case OP_STORE_VAR: {
                uint8_t mov_to_mem[] = {0x48, 0x89, 0x45, 0x00}; // mov [rbp - offset], rax
                mov_to_mem[3] = -c->locals[operand].stack_offset;
                emit_jit(c, (uint8_t[]){0x58}, 1); /* pop rax */
                emit_jit(c, mov_to_mem, sizeof(mov_to_mem));
                break;
            }
            case OP_LOAD_VAR: {
                uint8_t mov_from_mem[] = {0x48, 0x8b, 0x45, 0x00}; // mov rax, [rbp - offset]
                mov_from_mem[3] = -c->locals[operand].stack_offset;
                emit_jit(c, mov_from_mem, sizeof(mov_from_mem));
                emit_jit(c, (uint8_t[]){0x50}, 1); // push rax
                break;
            }
            case OP_JUMP_IF_FALSE: {
                emit_jit(c, (uint8_t[]){0x58}, 1); // pop rax
                emit_jit(c, (uint8_t[]){0x48, 0x85, 0xc0}, 3); // test rax, rax
                emit_jit(c, (uint8_t[]){0x0f, 0x84, 0x00, 0x00, 0x00, 0x00}, 6); // jz <offset>
                c->jump_patch_locs[c->jump_patch_count] = c->jit_size - 4;
                c->jump_patch_targets[c->jump_patch_count] = operand;
                c->jump_patch_count++;
                break;
            }
            case OP_JUMP: {
                emit_jit(c, (uint8_t[]){0xe9, 0x00, 0x00, 0x00, 0x00}, 5); // jmp <offset>
                c->jump_patch_locs[c->jump_patch_count] = c->jit_size - 4;
                c->jump_patch_targets[c->jump_patch_count] = operand;
                c->jump_patch_count++;
                break;
            }
            case OP_RETURN: {
                emit_jit(c, (uint8_t[]){0x58}, 1); // pop rax
                emit_jit(c, (uint8_t[]){0x48, 0x89, 0xec}, 3); // mov rsp, rbp
                emit_jit(c, (uint8_t[]){0x5d}, 1); // pop rbp
                emit_jit(c, (uint8_t[]){0xc3}, 1); // ret
                break;
            }
            default: break;
        }
    }
}
#else
void jit_compile(Compiler* c) { fail("JIT compilation is only supported on x86-64."); }
#endif

// ======================= COMPILER & EXECUTION =======================
void init_compiler(Compiler* c, const char* source, int opt_level) {
    memset(c, 0, sizeof(Compiler));
    c->source = source; c->cursor = source; c->line = 1; c->col = 1;
    c->optimization_level = opt_level;
}

void compile(Compiler* c) {
    get_next_token(c); // Prime the lexer
    c->ast_root = parse_statement(c); // For now, only one top-level statement (main)
    if(c->optimization_level > 0) optimize_ast(c, c->ast_root);
    emit_bytecode_from_ast(c, c->ast_root);
    c->jit_buf = mmap(NULL, MAX_CODE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (c->jit_buf == MAP_FAILED) fail("mmap failed.");
    jit_compile(c);
}

int execute(Compiler* c) {
    if (mprotect(c->jit_buf, c->jit_size, PROT_READ | PROT_EXEC) == -1) fail("mprotect failed.");
    int (*jit_func)() = (int(*)())c->jit_buf;
    int result = jit_func();
    munmap(c->jit_buf, MAX_CODE_SIZE);
    return result;
}
