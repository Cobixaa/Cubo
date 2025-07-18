
    // CUBO ARCHITECTURE V4.1 (Cross-Platform, Multi-Arch, Optimizing JIT)
// A multi-stage JIT compiler for a C subset with variables, expressions,
// if-else, while loops, and multiple optimization levels.
//
// FIXES IN V4.1:
// - Corrected all AArch64 macro definitions to be type-safe (casting to uint8_t*).
// - Wrapped macro bodies in do{...}while(0) to prevent variable redefinition errors and fix C90 compliance.
// - Defined a named 'JumpPatch' struct to fix incompatible anonymous struct assignment errors.
// - Created a common RETURN_OP macro to fix architecture-specific return sequence errors.
//
// To Compile:
//   clang -O2 -o cubo cubo.c
//
// To Run:
//   ./cubo -c0 your_file.c   (No optimizations)
//   ./cubo -c1 your_file.c   (AST Constant Folding)
//   ./cubo -c2 your_file.c   (AST Folding + Bytecode Peephole Optimization)
//

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>

// ────────────────────────────────────────────────────────────────────────────
//  Platform Abstraction Layer (PAL)
// ────────────────────────────────────────────────────────────────────────────
#ifdef _WIN32
#include <windows.h>
#else // POSIX-like systems (Linux, macOS, Termux)
#include <sys/mman.h>
#include <unistd.h>
#endif

void* pal_alloc_exec_mem(size_t size) {
#ifdef _WIN32
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    void* mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (mem == MAP_FAILED) ? NULL : mem;
#endif
}

bool pal_protect_exec(void* mem, size_t size) {
#ifdef _WIN32
    DWORD old_protect;
    return VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old_protect) != 0;
#else
    return mprotect(mem, size, PROT_READ | PROT_EXEC) == 0;
#endif
}

void pal_free_exec_mem(void* mem, size_t size) {
#ifdef _WIN32
    VirtualFree(mem, 0, MEM_RELEASE);
#else
    munmap(mem, size);
#endif
}

// ────────────────────────────────────────────────────────────────────────────
//  Data Structures & Forward Declarations
// ────────────────────────────────────────────────────────────────────────────
#define MAX_LOCALS 256
#define MAX_CODE_SIZE 65536
#define MAX_JUMP_PATCHES 256

typedef enum {
    T_EOF, T_UNKNOWN, T_INT, T_RETURN, T_IF, T_ELSE, T_WHILE,
    T_IDENTIFIER, T_INTEGER_LITERAL, T_PLUS, T_MINUS, T_STAR, T_SLASH,
    T_EQ, T_EQ_EQ, T_NOT_EQ, T_LT, T_LTE, T_GT, T_GTE,
    T_LPAREN, T_RPAREN, T_LBRACE, T_RBRACE, T_SEMICOLON,
} TokenType;

typedef struct { TokenType type; const char *start; int length; int line; int col; } Token;
typedef enum { NODE_NUMBER, NODE_VAR, NODE_UNARY, NODE_BINARY, NODE_ASSIGN, NODE_VAR_DECL, NODE_RETURN, NODE_IF, NODE_WHILE, NODE_BLOCK, } NodeType;
typedef struct ASTNode { NodeType type; struct ASTNode *next; Token token; struct ASTNode *left, *right, *condition, *then_branch, *else_branch, *body, *statements; int var_index; } ASTNode;
typedef enum { OP_NOP, OP_PUSH, OP_POP, OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_EQ, OP_NEQ, OP_LT, OP_GT, OP_STORE_VAR, OP_LOAD_VAR, OP_JUMP, OP_JUMP_IF_FALSE, OP_RETURN, } OpCode;
typedef struct { const char* name; int stack_offset; int depth; } LocalVar;
typedef struct { int loc; int target; } JumpPatch;

typedef struct Compiler {
    const char *source; const char *cursor; int line, col;
    Token current_token, prev_token; ASTNode *ast_root;
    LocalVar locals[MAX_LOCALS]; int local_count, scope_depth, stack_top;
    uint8_t code[MAX_CODE_SIZE]; int32_t code_operands[MAX_CODE_SIZE]; int code_count;
    uint8_t *jit_buf; size_t jit_size;
    JumpPatch jump_patches[MAX_JUMP_PATCHES]; int jump_patch_count;
    int optimization_level;
} Compiler;

void fail(const char *fmt, ...);
void fail_at(int line, int col, const char *fmt, ...);
void compile(Compiler* c);
int execute(Compiler* c);

// ────────────────────────────────────────────────────────────────────────────
//  Main Driver
// ────────────────────────────────────────────────────────────────────────────
int main(int argc, char **argv) {
    if (argc < 2) fail("Usage: %s [-c0|-c1|-c2] <file.c>", argv[0]);
    int opt_level = 0; const char *filepath = NULL;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-c0") == 0) opt_level = 0;
        else if (strcmp(argv[i], "-c1") == 0) opt_level = 1;
        else if (strcmp(argv[i], "-c2") == 0) opt_level = 2;
        else if (!filepath) filepath = argv[i];
        else fail("Too many file arguments.");
    }
    if (!filepath) fail("No source file provided.");

    FILE *file = fopen(filepath, "rb");
    if (!file) fail("Could not open file '%s'", filepath);
    fseek(file, 0, SEEK_END); long length = ftell(file); fseek(file, 0, SEEK_SET);
    char *source = malloc(length + 1);
    if (!source || fread(source, 1, length, file) != (size_t)length) fail("Could not read file '%s'", filepath);
    source[length] = '\0'; fclose(file);

    Compiler compiler = {0};
    compiler.source = source; compiler.cursor = source; compiler.line = 1; compiler.col = 1;
    compiler.optimization_level = opt_level;
    
    compile(&compiler);
    int exit_code = execute(&compiler);
    free(source); return exit_code;
}

// ┌──────────────────────────────────────────────────────────────────────────┐
// │                  FULL IMPLEMENTATION DETAILS BELOW                       │
// └──────────────────────────────────────────────────────────────────────────┘

// Utility Functions
void fail(const char *fmt, ...) { fprintf(stderr, "Error: "); va_list args; va_start(args, fmt); vfprintf(stderr, fmt, args); va_end(args); fprintf(stderr, "\n"); exit(1); }
void fail_at(int line, int col, const char *fmt, ...) { fprintf(stderr, "Error at line %d, col %d: ", line, col); va_list args; va_start(args, fmt); vfprintf(stderr, fmt, args); va_end(args); fprintf(stderr, "\n"); exit(1); }

// ======================= LEXER =======================
void advance_lexer(Compiler* c) { if (*c->cursor == '\n') { c->line++; c->col = 1; } else { c->col++; } c->cursor++; }
Token make_token(Compiler* c, TokenType type, const char* s, int l) { return (Token){type,s,l,c->line,c->col-l}; }
void get_next_token(Compiler* c) {
    c->prev_token = c->current_token;
    while (isspace(*c->cursor)) advance_lexer(c);
    const char* start = c->cursor;
    if (*c->cursor == '\0') { c->current_token = make_token(c, T_EOF, start, 0); return; }
    if (isalpha(*c->cursor) || *c->cursor == '_') {
        while (isalnum(*c->cursor) || *c->cursor == '_') advance_lexer(c); int len = c->cursor - start;
        #define KEYWORD(s, t) if (len == strlen(s) && strncmp(start, s, len) == 0) { c->current_token = make_token(c, t, start, len); return; }
        KEYWORD("int", T_INT); KEYWORD("return", T_RETURN); KEYWORD("if", T_IF);
        KEYWORD("else", T_ELSE); KEYWORD("while", T_WHILE);
        #undef KEYWORD
        c->current_token = make_token(c, T_IDENTIFIER, start, len); return;
    }
    if (isdigit(*c->cursor)) { while (isdigit(*c->cursor)) advance_lexer(c); c->current_token = make_token(c, T_INTEGER_LITERAL, start, c->cursor - start); return; }
    advance_lexer(c);
    switch (*start) {
        case '+': c->current_token=make_token(c, T_PLUS, start, 1); return; case '-': c->current_token=make_token(c, T_MINUS, start, 1); return;
        case '*': c->current_token=make_token(c, T_STAR, start, 1); return; case '/': c->current_token=make_token(c, T_SLASH, start, 1); return;
        case '(': c->current_token=make_token(c, T_LPAREN, start, 1); return; case ')': c->current_token=make_token(c, T_RPAREN, start, 1); return;
        case '{': c->current_token=make_token(c, T_LBRACE, start, 1); return; case '}': c->current_token=make_token(c, T_RBRACE, start, 1); return;
        case ';': c->current_token=make_token(c, T_SEMICOLON, start, 1); return;
        case '<': c->current_token=make_token(c, *c->cursor=='='?(advance_lexer(c),T_LTE):T_LT,start,c->cursor-start); return;
        case '>': c->current_token=make_token(c, *c->cursor=='='?(advance_lexer(c),T_GTE):T_GT,start,c->cursor-start); return;
        case '=': c->current_token=make_token(c, *c->cursor=='='?(advance_lexer(c),T_EQ_EQ):T_EQ,start,c->cursor-start); return;
        case '!': c->current_token=make_token(c, *c->cursor=='='?(advance_lexer(c),T_NOT_EQ):T_UNKNOWN,start,c->cursor-start); return;
    }
    c->current_token = make_token(c, T_UNKNOWN, start, 1);
}
void consume(Compiler* c, TokenType type, const char* msg) { if (c->current_token.type == type) get_next_token(c); else fail_at(c->current_token.line, c->current_token.col, "%s", msg); }

// ======================= PARSER (Builds AST) =======================
ASTNode* new_ast_node(NodeType type, Token token) { ASTNode* node = calloc(1, sizeof(ASTNode)); if (!node) fail("AST node allocation failed."); node->type = type; node->token = token; return node; }
ASTNode* parse_expression(Compiler* c); ASTNode* parse_statement(Compiler* c);
ASTNode* parse_primary(Compiler* c) {
    if (c->current_token.type == T_INTEGER_LITERAL) { ASTNode* n = new_ast_node(NODE_NUMBER, c->current_token); get_next_token(c); return n; }
    if (c->current_token.type == T_IDENTIFIER) { ASTNode* n = new_ast_node(NODE_VAR, c->current_token); get_next_token(c); return n; }
    if (c->current_token.type == T_LPAREN) { get_next_token(c); ASTNode* n = parse_expression(c); consume(c, T_RPAREN, "Expected ')' after expression."); return n; }
    fail_at(c->current_token.line, c->current_token.col, "Unexpected token in expression."); return NULL;
}
ASTNode* parse_binary(Compiler* c, ASTNode* (*higher_prec)(Compiler*), TokenType t1, TokenType t2, TokenType t3, TokenType t4) {
    ASTNode* node = higher_prec(c);
    while (c->current_token.type==t1 || c->current_token.type==t2 || c->current_token.type==t3 || c->current_token.type==t4) {
        Token op = c->current_token; get_next_token(c); ASTNode* right = higher_prec(c);
        ASTNode* b = new_ast_node(NODE_BINARY, op); b->left = node; b->right = right; node = b;
    } return node;
}
ASTNode* parse_term(Compiler* c) { return parse_binary(c, parse_primary, T_STAR, T_SLASH, T_UNKNOWN, T_UNKNOWN); }
ASTNode* parse_addition(Compiler* c) { return parse_binary(c, parse_term, T_PLUS, T_MINUS, T_UNKNOWN, T_UNKNOWN); }
ASTNode* parse_comparison(Compiler* c) { return parse_binary(c, parse_addition, T_LT, T_LTE, T_GT, T_GTE); }
ASTNode* parse_equality(Compiler* c) { return parse_binary(c, parse_comparison, T_EQ_EQ, T_NOT_EQ, T_UNKNOWN, T_UNKNOWN); }
ASTNode* parse_assignment(Compiler* c) {
    ASTNode* left = parse_equality(c);
    if (c->current_token.type == T_EQ) {
        if (left->type != NODE_VAR) fail_at(left->token.line, left->token.col, "Invalid assignment target.");
        Token op = c->current_token; get_next_token(c); ASTNode* right = parse_assignment(c);
        ASTNode* an = new_ast_node(NODE_ASSIGN, op); an->left = left; an->right = right; return an;
    } return left;
}
ASTNode* parse_expression(Compiler* c) { return parse_assignment(c); }

void begin_scope(Compiler* c) { c->scope_depth++; }
void end_scope(Compiler* c) {
    c->scope_depth--;
    while(c->local_count > 0 && c->locals[c->local_count - 1].depth > c->scope_depth) {
        int old_stack_top = c->stack_top;
        c->local_count--;
        c->stack_top = (c->local_count > 0) ? c->locals[c->local_count - 1].stack_offset : 0;
    }
}
ASTNode* parse_block(Compiler* c) {
    Token brace = c->current_token; consume(c, T_LBRACE, "Expected '{' to start a block."); begin_scope(c);
    ASTNode *head = NULL, *tail = NULL;
    while (c->current_token.type != T_RBRACE && c->current_token.type != T_EOF) {
        ASTNode* stmt = parse_statement(c);
        if (!head) head = tail = stmt; else { tail->next = stmt; tail = stmt; }
    }
    consume(c, T_RBRACE, "Expected '}' to end a block."); end_scope(c);
    ASTNode* block_node = new_ast_node(NODE_BLOCK, brace); block_node->statements = head;
    return block_node;
}
ASTNode* parse_statement(Compiler* c) {
    Token T = c->current_token;
    if (T.type == T_RETURN) { get_next_token(c); ASTNode* n=new_ast_node(NODE_RETURN, T); n->left=parse_expression(c); consume(c, T_SEMICOLON, "Expected ';'"); return n; }
    if (T.type == T_INT) { get_next_token(c); Token id=c->current_token; consume(c, T_IDENTIFIER, "Expected identifier"); ASTNode* d=new_ast_node(NODE_VAR_DECL, id); if (c->current_token.type==T_EQ) { get_next_token(c); ASTNode* a=new_ast_node(NODE_ASSIGN,c->prev_token); a->left=new_ast_node(NODE_VAR,id); a->right=parse_expression(c); d->left=a; } consume(c,T_SEMICOLON,"Expected ';'"); return d; }
    if (T.type == T_IF) { get_next_token(c); consume(c, T_LPAREN, "Expected '('"); ASTNode* n=new_ast_node(NODE_IF,T); n->condition=parse_expression(c); consume(c,T_RPAREN,"Expected ')'"); n->then_branch=parse_statement(c); if(c->current_token.type==T_ELSE){get_next_token(c); n->else_branch=parse_statement(c);} return n; }
    if (T.type == T_WHILE) { get_next_token(c); consume(c,T_LPAREN,"Expected '('"); ASTNode* n=new_ast_node(NODE_WHILE,T); n->condition=parse_expression(c); consume(c,T_RPAREN,"Expected ')'"); n->body=parse_statement(c); return n; }
    if (T.type == T_LBRACE) return parse_block(c);
    ASTNode* expr = parse_expression(c); consume(c, T_SEMICOLON, "Expected ';'"); return expr;
}

// ======================= OPTIMIZER =======================
bool eval_ast(ASTNode* node, int* result) {
    if (node->type == NODE_NUMBER) { *result = strtol(node->token.start, NULL, 10); return true; }
    if (node->type == NODE_BINARY) {
        int l, r; if (eval_ast(node->left, &l) && eval_ast(node->right, &r)) {
            switch (node->token.type) {
                case T_PLUS: *result=l+r; return true; case T_MINUS: *result=l-r; return true;
                case T_STAR: *result=l*r; return true; case T_SLASH: *result=r!=0?l/r:0; return true;
                case T_EQ_EQ: *result=l==r; return true; case T_NOT_EQ: *result=l!=r; return true;
                case T_LT: *result=l<r; return true; case T_LTE: *result=l<=r; return true;
                case T_GT: *result=l>r; return true; case T_GTE: *result=l>=r; return true;
                default: break;
            }
        }
    } return false;
}
void optimize_ast(Compiler* c, ASTNode** node_ptr) {
    ASTNode* node = *node_ptr; if (!node) return;
    optimize_ast(c, &node->left); optimize_ast(c, &node->right); optimize_ast(c, &node->condition); optimize_ast(c, &node->then_branch);
    optimize_ast(c, &node->else_branch); optimize_ast(c, &node->body); optimize_ast(c, &node->statements); optimize_ast(c, &node->next);
    if (c->optimization_level >= 1 && node->type == NODE_BINARY) {
        int result; if (eval_ast(node, &result)) {
            char* buf = malloc(32); snprintf(buf, 32, "%d", result);
            ASTNode* new_node = new_ast_node(NODE_NUMBER, node->token); new_node->token.start=buf;
            // Memory leak here for simplicity, but shows the concept. Free old node.
            *node_ptr = new_node;
        }
    }
}
void optimize_bytecode(Compiler* c) {
    if (c->optimization_level < 2) return;
    uint8_t new_code[MAX_CODE_SIZE]; int32_t new_ops[MAX_CODE_SIZE]; int new_count = 0;
    for (int i = 0; i < c->code_count; ++i) {
        if (i + 1 < c->code_count && c->code[i] == OP_PUSH && c->code[i+1] == OP_POP) { i++; continue; } // PUSH/POP elimination
        new_code[new_count] = c->code[i]; new_ops[new_count] = c->code_operands[i]; new_count++;
    }
    memcpy(c->code, new_code, new_count); memcpy(c->code_operands, new_ops, new_count * sizeof(int32_t));
    c->code_count = new_count;
}

// ======================= BYTECODE EMITTER =======================
void emit_op(Compiler* c, OpCode op, int32_t opd) { c->code[c->code_count]=op; c->code_operands[c->code_count]=opd; c->code_count++; }
int add_local(Compiler* c, Token name) {
    for (int i=c->local_count-1; i>=0 && c->locals[i].depth==c->scope_depth; --i) if (name.length == strlen(c->locals[i].name) && strncmp(name.start,c->locals[i].name,name.length)==0) fail_at(name.line,name.col,"Variable '%.*s' already declared in this scope",name.length,name.start);
    c->locals[c->local_count].name=strndup(name.start,name.length); c->locals[c->local_count].depth=c->scope_depth;
    c->stack_top+=8; c->locals[c->local_count].stack_offset=c->stack_top; return c->local_count++;
}
int find_local(Compiler* c, Token name) { for(int i=c->local_count-1;i>=0;--i) if(name.length==strlen(c->locals[i].name) && strncmp(name.start,c->locals[i].name,name.length)==0) return i; fail_at(name.line,name.col,"Undeclared variable '%.*s'",name.length,name.start); return -1; }
void emit_bytecode_from_ast(Compiler* c, ASTNode* node) {
    if (!node) return;
    switch (node->type) {
        case NODE_NUMBER: emit_op(c, OP_PUSH, strtol(node->token.start, NULL, 10)); break;
        case NODE_VAR_DECL: node->var_index = add_local(c, node->token); if (node->left) emit_bytecode_from_ast(c, node->left); break;
        case NODE_VAR: node->var_index = find_local(c, node->token); emit_op(c, OP_LOAD_VAR, node->var_index); break;
        case NODE_ASSIGN: node->left->var_index=find_local(c,node->left->token); emit_bytecode_from_ast(c,node->right); emit_op(c,OP_STORE_VAR,node->left->var_index); break;
        case NODE_BINARY: emit_bytecode_from_ast(c,node->left); emit_bytecode_from_ast(c,node->right);
            #define BIN_CASE(tok, op) if(node->token.type==tok) emit_op(c,op,0)
            BIN_CASE(T_PLUS,OP_ADD); BIN_CASE(T_MINUS,OP_SUB); BIN_CASE(T_STAR,OP_MUL); BIN_CASE(T_SLASH,OP_DIV);
            BIN_CASE(T_EQ_EQ,OP_EQ); BIN_CASE(T_NOT_EQ,OP_NEQ); BIN_CASE(T_LT,OP_LT); BIN_CASE(T_GT,OP_GT);
            #undef BIN_CASE
            break;
        case NODE_RETURN: emit_bytecode_from_ast(c, node->left); emit_op(c, OP_RETURN, 0); break;
        case NODE_BLOCK: { ASTNode* s = node->statements; while(s) { emit_bytecode_from_ast(c, s); s = s->next; } break; }
        case NODE_IF: {
            emit_bytecode_from_ast(c, node->condition); int else_jump = c->code_count; emit_op(c, OP_JUMP_IF_FALSE, 0);
            emit_bytecode_from_ast(c, node->then_branch);
            if (node->else_branch) { int exit_jump = c->code_count; emit_op(c, OP_JUMP, 0); c->code_operands[else_jump]=c->code_count; emit_bytecode_from_ast(c,node->else_branch); c->code_operands[exit_jump]=c->code_count; }
            else { c->code_operands[else_jump] = c->code_count; } break;
        }
        case NODE_WHILE: {
            int loop_start = c->code_count; emit_bytecode_from_ast(c, node->condition);
            int exit_jump = c->code_count; emit_op(c, OP_JUMP_IF_FALSE, 0);
            emit_bytecode_from_ast(c, node->body); emit_op(c, OP_JUMP, loop_start);
            c->code_operands[exit_jump] = c->code_count; break;
        }
        default: emit_bytecode_from_ast(c, node->left);
    }
    if (node->type < NODE_RETURN || node->type > NODE_BLOCK) emit_bytecode_from_ast(c, node->next);
}

// ======================= JIT BACKEND (Multi-Arch) =======================
void jit_emit(Compiler* c, uint8_t* data, size_t size) { memcpy(c->jit_buf + c->jit_size, data, size); c->jit_size += size; }
void jit_compile(Compiler* c) {
    // *** FIX: Type-safe and C90-compliant macros using do{...}while(0) and proper casting ***
    #if defined(__x86_64__)
    #define PROLOGUE() do { jit_emit(c,(uint8_t[]){0x55,0x48,0x89,0xe5},4); if (c->stack_top > 0) { uint8_t sub_rsp[]={0x48,0x81,0xec,0,0,0,0}; *(uint32_t*)(sub_rsp+3)=c->stack_top; jit_emit(c,sub_rsp,sizeof(sub_rsp)); } } while(0)
    #define EPILOGUE() do { if (c->stack_top > 0) jit_emit(c,(uint8_t[]){0x48,0x89,0xec},3); jit_emit(c,(uint8_t[]){0x5d,0xc3},2); } while(0)
    #define POP_RAX() do { jit_emit(c,(uint8_t[]){0x58},1); } while(0)
    #define RETURN_OP() do { POP_RAX(); EPILOGUE(); } while(0)
    #define PUSH_IMM(opd) do { uint8_t p[]={0x68,0,0,0,0}; *(uint32_t*)(p+1)=(uint32_t)opd; jit_emit(c,p,5); } while(0)
    #define BIN_OP(add_op,sub_op,mul_op,div_op) do { uint8_t pop_rbx[]={0x5b}; uint8_t pop_rax[]={0x58}; uint8_t push_rax[]={0x50}; jit_emit(c,pop_rbx,1); jit_emit(c,pop_rax,1); if(op==OP_ADD)jit_emit(c,(uint8_t[])add_op,3); else if(op==OP_SUB)jit_emit(c,(uint8_t[])sub_op,3); else if(op==OP_MUL)jit_emit(c,(uint8_t[])mul_op,4); else if(op==OP_DIV){jit_emit(c,(uint8_t[]){0x99},1); jit_emit(c,(uint8_t[])div_op,3);} jit_emit(c,push_rax,1); } while(0)
    #define CMP_OP(setcc) do { uint8_t p_rbx[]={0x5b}, p_rax[]={0x58}, cmp[]={0x48,0x39,0xd8}, set[]={0x0f,setcc,0xc0}, movzx[]={0x48,0x0f,0xb6,0xc0}, push[]={0x50}; jit_emit(c,p_rbx,1); jit_emit(c,p_rax,1); jit_emit(c,cmp,3); jit_emit(c,set,3); jit_emit(c,movzx,4); jit_emit(c,push,1); } while(0)
    #define STORE_VAR(opd) do { uint8_t m[]={0x48,0x89,0x45,0};m[3]=(uint8_t)-c->locals[opd].stack_offset; POP_RAX(); jit_emit(c,m,4); } while(0)
    #define LOAD_VAR(opd) do { uint8_t m[]={0x48,0x8b,0x45,0};m[3]=(uint8_t)-c->locals[opd].stack_offset; jit_emit(c,m,4); jit_emit(c,(uint8_t[]){0x50},1); } while(0)
    #define JMP_IF_FALSE() do { POP_RAX(); jit_emit(c,(uint8_t[]){0x48,0x85,0xc0},3); jit_emit(c,(uint8_t[]){0x0f,0x84,0,0,0,0},6); c->jump_patches[c->jump_patch_count++]=(JumpPatch){(int)c->jit_size-4, operand}; } while(0)
    #define JMP() do { jit_emit(c,(uint8_t[]){0xe9,0,0,0,0},5); c->jump_patches[c->jump_patch_count++]=(JumpPatch){(int)c->jit_size-4, operand}; } while(0)
    #elif defined(__aarch64__)
    #define PROLOGUE() do { jit_emit(c, (uint8_t*)(uint32_t[]){0xa9bf7bfd, 0x910003fd}, 8); if (c->stack_top > 0) { uint32_t s = 0xd10003ff; int aligned_stack = (c->stack_top + 15) & ~15; if (aligned_stack > 0) { s |= ((aligned_stack/16)&0xfff)<<10; jit_emit(c,(uint8_t*)&s,4); } } } while(0)
    #define EPILOGUE() do { if (c->stack_top > 0) { uint32_t s = 0x910003ff; int aligned_stack = (c->stack_top + 15) & ~15; if (aligned_stack > 0) { s |= ((aligned_stack/16)&0xfff)<<10; jit_emit(c,(uint8_t*)&s,4); } } jit_emit(c, (uint8_t*)(uint32_t[]){0xa8c17bfd, 0xd65f03c0}, 8); } while(0)
    #define POP(reg) do { uint32_t i = 0xf84107e0 | (reg); jit_emit(c, (uint8_t*)&i, 4); } while(0)
    #define RETURN_OP() do { POP(0); EPILOGUE(); } while(0)
    #define PUSH_IMM(opd) do { uint32_t m[]={0xd2800000 | (((uint32_t)opd&0xffff)<<5), 0xf90003e0}; jit_emit(c,(uint8_t*)m,8); } while(0)
    #define BIN_OP(add_op,sub_op,mul_op,div_op) do { POP(1);POP(0); uint32_t i=0; if(op==OP_ADD)i=add_op; else if(op==OP_SUB)i=sub_op; else if(op==OP_MUL)i=mul_op; else if(op==OP_DIV)i=div_op; jit_emit(c,(uint8_t*)&i,4); uint32_t p = 0xf81f0fe0 | 0; jit_emit(c, (uint8_t*)&p, 4); } while(0)
    #define CMP_OP(cond) do { POP(1); POP(0); jit_emit(c,(uint8_t*)(uint32_t[]){0xeb01001f},4); uint32_t i=0x9a801000|(cond<<12); jit_emit(c,(uint8_t*)&i,4); uint32_t p = 0xf81f0fe0 | 0; jit_emit(c, (uint8_t*)&p, 4); } while(0)
    #define STORE_VAR(opd) do { uint32_t m=0xb90003a0 | ((c->locals[opd].stack_offset)&0xfff)<<10; POP(0); jit_emit(c,(uint8_t*)&m,4); } while(0)
    #define LOAD_VAR(opd) do { uint32_t m=0xb94003a0 | ((c->locals[opd].stack_offset)&0xfff)<<10; jit_emit(c,(uint8_t*)&m,4); uint32_t p = 0xf81f0fe0 | 0; jit_emit(c, (uint8_t*)&p, 4); } while(0)
    #define JMP_IF_FALSE() do { POP(0); jit_emit(c, (uint8_t*)(uint32_t[]){0xb4000000}, 4); c->jump_patches[c->jump_patch_count++]=(JumpPatch){(int)c->jit_size-4, operand}; } while(0)
    #define JMP() do { jit_emit(c, (uint8_t*)(uint32_t[]){0x14000000}, 4); c->jump_patches[c->jump_patch_count++]=(JumpPatch){(int)c->jit_size-4, operand}; } while(0)
    #else
    #error "Cubo JIT is not supported on this architecture."
    #endif
    
    PROLOGUE();
    int* jump_targets = calloc(c->code_count + 1, sizeof(int));
    for (int i=0; i < c->code_count; ++i) {
        jump_targets[i] = c->jit_size;
        OpCode op = c->code[i]; int32_t operand = c->code_operands[i];
        switch(op) {
            case OP_PUSH: PUSH_IMM(operand); break;
            case OP_ADD: case OP_SUB: case OP_MUL: case OP_DIV: BIN_OP(0x8b010000, 0xcb010000, 0x9b017c00, 0x9ac10c00); break;
            case OP_EQ: CMP_OP(0b0001); break; case OP_NEQ: CMP_OP(0b0000); break;
            case OP_LT: CMP_OP(0b1011); break; case OP_GT: CMP_OP(0b1101); break;
            case OP_STORE_VAR: STORE_VAR(operand); break;
            case OP_LOAD_VAR: LOAD_VAR(operand); break;
            case OP_JUMP_IF_FALSE: JMP_IF_FALSE(); break;
            case OP_JUMP: JMP(); break;
            case OP_RETURN: RETURN_OP(); break;
            default: break;
        }
    }
    jump_targets[c->code_count] = c->jit_size; // Target for jumps to the very end
    for (int i=0; i<c->jump_patch_count; ++i) {
        int patch_loc = c->jump_patches[i].loc; int target_loc = jump_targets[c->jump_patches[i].target];
        int32_t offset = target_loc - patch_loc;
        #if defined(__x86_64__)
        *(int32_t*)(c->jit_buf + patch_loc) = offset;
        #elif defined(__aarch64__)
        uint32_t* instr = (uint32_t*)(c->jit_buf + patch_loc);
        if ((*instr & 0xff000000) == 0xb4000000) *instr |= ((offset/4)&0x7ffff)<<5; // cbz
        else *instr |= ((offset/4)&0x3ffffff); // b
        #endif
    }
    free(jump_targets);
}

// ======================= COMPILER & EXECUTION =======================
void compile(Compiler* c) {
    get_next_token(c);
    consume(c, T_INT, "Expected 'int' at start of program.");
    consume(c, T_IDENTIFIER, "Expected 'main' after 'int'."); // Assuming main
    consume(c, T_LPAREN, "Expected '(' after 'main'."); consume(c, T_RPAREN, "Expected ')' after 'main()'.");
    c->ast_root = parse_statement(c);
    if(c->optimization_level >= 1) optimize_ast(c, &c->ast_root);
    emit_bytecode_from_ast(c, c->ast_root);
    if(c->optimization_level >= 2) optimize_bytecode(c);
    c->jit_buf = pal_alloc_exec_mem(MAX_CODE_SIZE); if (!c->jit_buf) fail("Failed to allocate executable memory.");
    jit_compile(c);
}
int execute(Compiler* c) {
    if (!pal_protect_exec(c->jit_buf, c->jit_size)) fail("Failed to make memory executable.");
    int (*jit_func)() = (int(*)())c->jit_buf;
    int result = jit_func();
    pal_free_exec_mem(c->jit_buf, c->jit_size);
    return result;
}
