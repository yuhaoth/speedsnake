#!/usr/bin/env python3
#
# Speedsnake (http://code.google.com/p/speedsnake/)
# Copyright (c) 2013-2015 Matt Craighead
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
# associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute,
# sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
# NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
# OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import argparse
import io

import lex
import yacc

tokens = [
    'IDENTIFIER', 'INT_LITERAL', 'STRING_LITERAL',
    'PLUS', 'MINUS', 'STAR', 'SLASH', 'PERCENT', 'AMPERSAND', 'PIPE', 'CARET', 'TILDE', 'EQUALS',
    'PERIOD', 'COMMA', 'COLON',
    'LESS', 'LESS_EQUALS', 'GREATER', 'GREATER_EQUALS', 'EXCLAMATION_EQUALS', 'EQUALS_EQUALS',
    'PLUS_EQUALS', 'MINUS_EQUALS', 'STAR_EQUALS', 'SLASH_EQUALS', 'SLASH_SLASH_EQUALS', 'PERCENT_EQUALS',
    'AMPERSAND_EQUALS', 'PIPE_EQUALS', 'CARET_EQUALS',
    'SLASH_SLASH', 'STAR_STAR', 'LESS_LESS', 'GREATER_GREATER', 'GREATER_GREATER_GREATER',
    'LESS_LESS_EQUALS', 'GREATER_GREATER_EQUALS', 'GREATER_GREATER_GREATER_EQUALS',
    'LPAREN', 'RPAREN', 'LBRACKET', 'RBRACKET', 'LBRACE', 'RBRACE',
    'NEWLINE', 'INDENT', 'DEDENT',
]

# XXX import, export, do/while, yield, elif, in/not in, and/or/not, lambda
reserved = ['assert', 'break', 'continue', 'def', 'else', 'for', 'if', 'in', 'pass', 'return', 'verify', 'while']
tokens += [x.upper() for x in reserved]
reserved = {x: x.upper() for x in reserved}

t_ignore = ' '

def t_COMMENT(t):
    r'\#.*'
    pass

def t_IDENTIFIER(t):
    r'[A-Za-z_][A-Za-z0-9_]*'
    t.type = reserved.get(t.value, 'IDENTIFIER')
    return t

t_INT_LITERAL = r'(0(x[0-9A-Fa-f]+)?)|([1-9][0-9]*)'
t_STRING_LITERAL = r'(\'[0-9A-Za-z_]*\')|("[0-9A-Za-z_]*")' # XXX not even close to complete

t_PLUS      = r'\+'
t_MINUS     = r'-'
t_STAR      = r'\*'
t_SLASH     = r'/'
t_PERCENT   = r'%'
t_AMPERSAND = r'&'
t_PIPE      = r'\|'
t_CARET     = r'\^'
t_TILDE     = r'~'
t_EQUALS    = r'='
t_PERIOD    = r'\.'
t_COMMA     = r','
t_COLON     = r':'

t_LESS                           = r'<'
t_LESS_EQUALS                    = r'<='
t_GREATER                        = r'>'
t_GREATER_EQUALS                 = r'>='
t_EXCLAMATION_EQUALS             = r'!='
t_EQUALS_EQUALS                  = r'=='
t_PLUS_EQUALS                    = r'\+='
t_MINUS_EQUALS                   = r'-='
t_STAR_EQUALS                    = r'\*='
t_SLASH_EQUALS                   = r'/='
t_SLASH_SLASH_EQUALS             = r'//='
t_PERCENT_EQUALS                 = r'%='
t_AMPERSAND_EQUALS               = r'&='
t_PIPE_EQUALS                    = r'\|='
t_CARET_EQUALS                   = r'\^='
t_SLASH_SLASH                    = r'//'
t_STAR_STAR                      = r'\*\*'
t_LESS_LESS                      = r'<<'
t_GREATER_GREATER                = r'>>'
t_GREATER_GREATER_GREATER        = r'>>>'
t_LESS_LESS_EQUALS               = r'<<='
t_GREATER_GREATER_EQUALS         = r'>>='
t_GREATER_GREATER_GREATER_EQUALS = r'>>>='

t_LPAREN    = r'\('
t_RPAREN    = r'\)'
t_LBRACKET  = r'\['
t_RBRACKET  = r'\]'
t_LBRACE    = r'{'
t_RBRACE    = r'}'

indents = [0] # assume first line has no indent

def t_NEWLINE(t):
    r'\n'
    pos = t.lexer.lexpos
    while pos < len(t.lexer.lexdata) and t.lexer.lexdata[pos] == ' ':
        pos += 1
    indents.append(pos - t.lexer.lexpos)
    t.lexer.lineno += 1
    return t

def t_error(t):
    print("Illegal character '%s'" % t.value[0])
    exit(1)

precedence = (
    ('left', 'LESS', 'LESS_EQUALS', 'GREATER', 'GREATER_EQUALS', 'EXCLAMATION_EQUALS', 'EQUALS_EQUALS'),
    ('left', 'PIPE'),
    ('left', 'CARET'),
    ('left', 'AMPERSAND'),
    ('left', 'LESS_LESS', 'GREATER_GREATER', 'GREATER_GREATER_GREATER'),
    ('left', 'PLUS', 'MINUS'),
    ('left', 'STAR', 'SLASH', 'SLASH_SLASH', 'PERCENT'),
)

# program: (NEWLINE | statement)*
def p_program_1(p):
    """program : NEWLINE"""
    p[0] = []
def p_program_2(p):
    """program : statement"""
    p[0] = p[1]
def p_program_3(p):
    """program : NEWLINE program"""
    p[0] = p[2]
def p_program_4(p):
    """program : statement program"""
    p[0] = p[1] + p[2]

# statement: PASS NEWLINE
#          | BREAK NEWLINE
#          | CONTINUE NEWLINE
#          | expression NEWLINE
#          | IDENTIFIER <assign-op> expression NEWLINE
#          | RETURN NEWLINE
#          | RETURN expression NEWLINE
#          | ASSERT expression NEWLINE
#          | VERIFY expression NEWLINE
#          | IF expression ':' suite [ELSE ':' suite]
#          | WHILE expression ':' suite
#          | FOR expression IN expression ':' suite
#          | DEF IDENTIFIER '(' [parameter_list] ')' ':' suite
def p_statement_1(p):
    """statement : PASS NEWLINE"""
    p[0] = []
def p_statement_2(p):
    """statement : BREAK NEWLINE"""
    p[0] = [BreakStatement()]
def p_statement_3(p):
    """statement : CONTINUE NEWLINE"""
    p[0] = [ContinueStatement()]
def p_statement_4(p):
    """statement : expression NEWLINE"""
    p[0] = [p[1]]
def p_statement_5(p):
    """statement : IDENTIFIER EQUALS expression NEWLINE
                 | IDENTIFIER PLUS_EQUALS expression NEWLINE
                 | IDENTIFIER MINUS_EQUALS expression NEWLINE
                 | IDENTIFIER STAR_EQUALS expression NEWLINE
                 | IDENTIFIER SLASH_EQUALS expression NEWLINE
                 | IDENTIFIER SLASH_SLASH_EQUALS expression NEWLINE
                 | IDENTIFIER PERCENT_EQUALS expression NEWLINE
                 | IDENTIFIER AMPERSAND_EQUALS expression NEWLINE
                 | IDENTIFIER CARET_EQUALS expression NEWLINE
                 | IDENTIFIER PIPE_EQUALS expression NEWLINE
                 | IDENTIFIER LESS_LESS_EQUALS expression NEWLINE
                 | IDENTIFIER GREATER_GREATER_EQUALS expression NEWLINE
                 | IDENTIFIER GREATER_GREATER_GREATER_EQUALS expression NEWLINE"""
    p[0] = [AssignStatement(p[2], Identifier(p[1]), p[3])]
def p_statement_6(p):
    """statement : RETURN NEWLINE"""
    p[0] = [ReturnStatement()]
def p_statement_7(p):
    """statement : RETURN expression NEWLINE"""
    p[0] = [ReturnStatement(p[2])]
def p_statement_8(p):
    """statement : ASSERT expression NEWLINE"""
    p[0] = [AssertStatement(p[2])]
def p_statement_9(p):
    """statement : VERIFY expression NEWLINE"""
    p[0] = [VerifyStatement(p[2])]
def p_statement_10(p):
    """statement : IF expression COLON suite"""
    p[0] = [IfStatement(p[2], p[4], [])]
def p_statement_11(p):
    """statement : IF expression COLON suite ELSE COLON suite"""
    p[0] = [IfStatement(p[2], p[4], p[7])]
def p_statement_12(p):
    """statement : WHILE expression COLON suite"""
    p[0] = [WhileStatement(p[2], p[4])]
def p_statement_13(p):
    """statement : FOR IDENTIFIER IN expression COLON suite"""
    p[0] = [ForStatement(p[2], p[4], p[6])]
def p_statement_14(p):
    """statement : DEF IDENTIFIER LPAREN RPAREN COLON suite"""
    p[0] = [DefStatement(p[2], [], p[6])]
def p_statement_15(p):
    """statement : DEF IDENTIFIER LPAREN parameter_list RPAREN COLON suite"""
    p[0] = [DefStatement(p[2], p[4], p[7])]

# parameter_list: IDENTIFIER
#               | IDENTIFIER COMMA parameter_list
def p_parameter_list_1(p):
    """parameter_list : IDENTIFIER"""
    p[0] = [p[1]]
def p_parameter_list_2(p):
    """parameter_list : IDENTIFIER COMMA parameter_list"""
    p[0] = [p[1]] + p[3]

# suite: NEWLINE INDENT statement+ DEDENT
def p_suite(p):
    """suite : NEWLINE INDENT statement_plus DEDENT"""
    p[0] = p[3]
def p_statement_plus_1(p):
    """statement_plus : statement"""
    p[0] = p[1]
def p_statement_plus_2(p):
    """statement_plus : statement statement_plus"""
    p[0] = p[1] + p[2]

# XXX comparison chaining
# expr: u_expr
#     | expression <binary-op> expression
def p_expr_1(p):
    """expression : u_expr"""
    p[0] = p[1]
def p_expr_2(p):
    """expression : expression PLUS expression
                  | expression MINUS expression
                  | expression STAR expression
                  | expression SLASH expression
                  | expression SLASH_SLASH expression
                  | expression PERCENT expression
                  | expression AMPERSAND expression
                  | expression CARET expression
                  | expression PIPE expression
                  | expression LESS expression
                  | expression LESS_EQUALS expression
                  | expression GREATER expression
                  | expression GREATER_EQUALS expression
                  | expression EXCLAMATION_EQUALS expression
                  | expression EQUALS_EQUALS expression
                  | expression LESS_LESS expression
                  | expression GREATER_GREATER expression
                  | expression GREATER_GREATER_GREATER expression"""
    p[0] = BinaryOp(p[2], p[1], p[3])
def p_expr_3(p):
    """expression : LPAREN expression RPAREN"""
    p[0] = p[2]

# u_expr: power
#       | '-' u_expr
#       | '+' u_expr
#       | '~' u_expr
def p_u_expr_1(p):
    """u_expr : power"""
    p[0] = p[1]
def p_u_expr_2(p):
    """u_expr : MINUS u_expr
              | PLUS u_expr
              | TILDE u_expr"""
    p[0] = UnaryOp(p[1], p[2])

# power: primary ['**' u_expr]
def p_power_1(p):
    """power : primary"""
    p[0] = p[1]
def p_power_2(p):
    """power : primary STAR_STAR u_expr"""
    p[0] = BinaryOp(p[2], p[1], p[3])

# XXX slicings, kwargs, starargs
# primary: atom
#        | primary '.' IDENTIFIER
#        | primary '[' expression ']'
#        | primary '(' [expression_list] ')'
def p_primary_1(p):
    """primary : atom"""
    p[0] = p[1]
def p_primary_2(p):
    """primary : primary PERIOD IDENTIFIER"""
    p[0] = AttributeExpr(p[1], p[3])
def p_primary_3(p):
    """primary : primary LBRACKET expression RBRACKET"""
    p[0] = SubscriptExpr(p[1], p[3])
def p_primary_4(p):
    """primary : primary LPAREN RPAREN"""
    p[0] = FunctionCall(p[1], [])
def p_primary_5(p):
    """primary : primary LPAREN expression_list RPAREN"""
    p[0] = FunctionCall(p[1], p[3])

# expression_list: expression (',' expression)*
def p_expression_list_1(p):
    """expression_list : expression"""
    p[0] = [p[1]]
def p_expression_list(p):
    """expression_list : expression COMMA expression_list"""
    p[0] = [p[1]] + p[3]

# expression_list_comma: expression (',' expression)* [',']
def p_expression_list_comma_1(p):
    """expression_list_comma : expression
                             | expression COMMA"""
    p[0] = [p[1]]
def p_expression_list_comma_2(p):
    """expression_list_comma : expression COMMA expression_list_comma"""
    p[0] = [p[1]] + p[3]

# key_value_list_comma: expression COLON expression (',' expression COLON expression)* [',']
def p_key_value_list_comma_1(p):
    """key_value_list_comma : expression COLON expression
                            | expression COLON expression COMMA"""
    p[0] = [(p[1], p[3])]
def p_key_value_list_comma_2(p):
    """key_value_list_comma : expression COLON expression COMMA key_value_list_comma"""
    p[0] = [(p[1], p[3])] + p[5]

# atom: IDENTIFIER | INT_LITERAL | STRING_LITERAL
#     | '[' [expression_list_comma] ']'
#     | '{' [key_value_list_comma] '}'
def p_atom_1(p):
    """atom : IDENTIFIER"""
    p[0] = Identifier(p[1])
def p_atom_2(p):
    """atom : INT_LITERAL"""
    p[0] = IntLiteral(int(p[1], 0))
def p_atom_3(p):
    """atom : STRING_LITERAL"""
    s = p[1]
    if s.startswith("'"):
        assert s.endswith("'")
        s = s[1:-1]
    else:
        assert s.startswith('"')
        assert s.endswith('"')
        s = s[1:-1]
    p[0] = StrLiteral(s)
def p_atom_4(p):
    """atom : LBRACKET RBRACKET"""
    p[0] = ListLiteral([])
def p_atom_5(p):
    """atom : LBRACKET expression_list_comma RBRACKET"""
    p[0] = ListLiteral(p[2])
def p_atom_6(p):
    """atom : LBRACE RBRACE"""
    p[0] = DictLiteral([])
def p_atom_7(p):
    """atom : LBRACE key_value_list_comma RBRACE"""
    p[0] = DictLiteral(p[2])

def p_error(p):
    print('ERROR: syntax error in input file')

n_temps = 0

def flatten_expr_link(link, statements):
    global n_temps
    if not link.pred.is_atom():
        link.pred.flatten(statements) # first recursively flatten

        name = '$t%d' % n_temps
        n_temps += 1
        statements.append(AssignStatement('=', Identifier(name), link.pred))
        link.pred.uses.remove(link)
        link.pred = Identifier(name)
        link.pred.uses = [link]

class ExprLink:
    def __init__(self, pred, succ):
        self.pred = pred
        self.succ = succ
        pred.uses.append(self)

# XXX line number info
class Expr:
    def __init__(self):
        self.uses = []

    def forward(self, new):
        for link in self.uses:
            link.pred = new
        new.uses += self.uses
        self.uses = []

    def is_atom(self):
        return False

    def dead_code_elimination_allowed(self):
        return True

    def operands(self):
        for link in self.operand_links():
            yield link.pred

    def operand_links(self):
        return []

    def flatten(self, statements):
        pass

    def build_ssa(self, symbols):
        pass

    def lower(self):
        return self

class IntLiteral(Expr):
    def __init__(self, value):
        Expr.__init__(self)
        assert isinstance(value, int)
        self.value = value

    def __repr__(self):
        return '%d' % self.value

    def is_atom(self):
        return True

class StrLiteral(Expr):
    def __init__(self, value):
        Expr.__init__(self)
        assert isinstance(value, str)
        self.value = value

    def __repr__(self):
        return repr(self.value)

    def is_atom(self):
        return True

class BytesLiteral(Expr):
    def __init__(self, value):
        Expr.__init__(self)
        assert isinstance(value, bytes)
        self.value = value

    def __repr__(self):
        return repr(self.value)

    def is_atom(self):
        return True

class Identifier(Expr):
    def __init__(self, name):
        Expr.__init__(self)
        self.name = name

    def __repr__(self):
        return self.name

    def is_atom(self):
        return True

    def build_ssa(self, symbols):
        if self.name in symbols:
            self.forward(symbols[self.name])
        elif self.name in builtin_functions:
            self.forward(BuiltinFunction(self.name))
        else:
            raise RuntimeError("undefined global '%s'" % self.name)

class BuiltinFunction(Expr):
    def __init__(self, name):    
        Expr.__init__(self)
        self.name = name

    def __repr__(self):
        return '<builtin_%s>' % self.name

    def is_atom(self):
        return True

class Argument(Expr):
    def __init__(self, index):
        Expr.__init__(self)
        self.index = index

    def __repr__(self):
        return '<arg%d>' % self.index

    def is_atom(self):
        return False # can't be removed by DCE unless they are truly unused (won't affect flattening, which won't see them)

class Phi(Expr):
    def __init__(self):
        Expr.__init__(self)
        self.args = []

    def __repr__(self):
        return 'phi(%s)' % ', '.join(str(x) for x in args)

    def operand_links(self):
        for x in self.args:
            yield x

class CompileError(Expr):
    def __init__(self, msg):
        Expr.__init__(self)
        self.msg = msg

    def __repr__(self):
        return 'compile_error(%s)' % repr(self.msg)

    def is_atom(self):
        return True

class ListLiteral(Expr):
    def __init__(self, values):
        Expr.__init__(self)
        assert isinstance(values, list)
        self.values = [ExprLink(x, self) for x in values]

    def __repr__(self):
        return str([x.pred for x in self.values])

    def operand_links(self):
        for x in self.values:
            yield x

    def flatten(self, statements):
        for x in self.values:
            flatten_expr_link(x, statements)

    def build_ssa(self, symbols):
        for x in self.values:
            x.pred.build_ssa(symbols)

class DictLiteral(Expr):
    def __init__(self, values):
        Expr.__init__(self)
        self.values = [(ExprLink(k, self), ExprLink(v, self)) for (k, v) in values]

    def __repr__(self):
        return '{%s}' % ', '.join('%s: %s' % (x[0].pred, x[1].pred) for x in self.values)

    def operand_links(self):
        for (k, v) in self.values:
            yield k
            yield v

    def flatten(self, statements):
        for (k, v) in self.values:
            flatten_expr_link(k, statements)
            flatten_expr_link(v, statements)

    def build_ssa(self, symbols):
        for (k, v) in self.values:
            k.pred.build_ssa(symbols)
            v.pred.build_ssa(symbols)

class UnaryOp(Expr):
    def __init__(self, op, arg):
        Expr.__init__(self)
        self.op = op
        self.arg = ExprLink(arg, self)

    def __repr__(self):
        return '(%s%s)' % (self.op, self.arg.pred)

    def operand_links(self):
        yield self.arg

    def flatten(self, statements):
        flatten_expr_link(self.arg, statements)

    def build_ssa(self, symbols):
        self.arg.pred.build_ssa(symbols)

class BinaryOp(Expr):
    def __init__(self, op, lhs, rhs):
        Expr.__init__(self)
        self.op = op
        self.lhs = ExprLink(lhs, self)
        self.rhs = ExprLink(rhs, self)

    def __repr__(self):
        return '(%s %s %s)' % (self.lhs.pred, self.op, self.rhs.pred)

    def operand_links(self):
        yield self.lhs
        yield self.rhs

    def flatten(self, statements):
        flatten_expr_link(self.lhs, statements)
        flatten_expr_link(self.rhs, statements)

    def build_ssa(self, symbols):
        self.lhs.pred.build_ssa(symbols)
        self.rhs.pred.build_ssa(symbols)

    def lower(self):
        if self.op == '+':
            expr = FunctionCall(BuiltinFunction('add64'), [self.lhs.pred, self.rhs.pred])
            self.forward(expr)
            return expr
        elif self.op == '&':
            expr = FunctionCall(BuiltinFunction('and64'), [self.lhs.pred, self.rhs.pred])
            self.forward(expr)
            return expr
        elif self.op == '*':
            expr = FunctionCall(BuiltinFunction('mul64'), [self.lhs.pred, self.rhs.pred])
            self.forward(expr)
            return expr
        elif self.op == '>>>':
            expr = FunctionCall(BuiltinFunction('shr64'), [self.lhs.pred, self.rhs.pred])
            self.forward(expr)
            return expr
        return self

class SubscriptExpr(Expr):
    def __init__(self, lhs, rhs):
        Expr.__init__(self)
        self.lhs = ExprLink(lhs, self)
        self.rhs = ExprLink(rhs, self)

    def __repr__(self):
        return '(%s[%s])' % (self.lhs.pred, self.rhs.pred)

    def operand_links(self):
        yield self.lhs
        yield self.rhs

    def flatten(self, statements):
        flatten_expr_link(self.lhs, statements)
        flatten_expr_link(self.rhs, statements)

    def build_ssa(self, symbols):
        self.lhs.pred.build_ssa(symbols)
        self.rhs.pred.build_ssa(symbols)

class FunctionCall(Expr):
    def __init__(self, func, args):
        Expr.__init__(self)
        assert isinstance(args, list)
        self.func = ExprLink(func, self)
        self.args = [ExprLink(x, self) for x in args]

    def __repr__(self):
        return '%s(%s)' % (self.func.pred, ', '.join(str(x.pred) for x in self.args))

    def dead_code_elimination_allowed(self):
        return False

    def operand_links(self):
        yield self.func
        for x in self.args:
            yield x

    def flatten(self, statements):
        flatten_expr_link(self.func, statements)
        for x in self.args:
            flatten_expr_link(x, statements)

    def build_ssa(self, symbols):
        self.func.pred.build_ssa(symbols)
        for x in self.args:
            x.pred.build_ssa(symbols)

    def lower(self):
        assert isinstance(self.func.pred, BuiltinFunction) # all remaining function calls should be to builtin functions
        return self

class AssignStatement(Expr):
    def __init__(self, op, lhs, rhs):
        Expr.__init__(self)
        assert isinstance(lhs, Identifier)
        self.op = op
        self.lhs = lhs
        self.rhs = ExprLink(rhs, self)

    def __repr__(self):
        return '%s %s %s' % (self.lhs, self.op, self.rhs.pred)

    def operand_links(self):
        yield self.rhs

    def flatten(self, statements):
        self.rhs.pred.flatten(statements)

    def build_ssa(self, symbols):
        self.rhs.pred.build_ssa(symbols)
        symbols[self.lhs.name] = self.rhs.pred

class IfStatement(Expr):
    def __init__(self, cond, if_body, else_body):
        Expr.__init__(self)
        assert isinstance(if_body, list)
        assert isinstance(else_body, list)
        self.cond = cond
        self.if_body = if_body
        self.else_body = else_body

    def __repr__(self):
        lines = ['if %s:' % self.cond]
        for s in self.if_body:
            for line in str(s).splitlines():
                lines += ['    %s' % line]
        if self.else_body:
            lines += ['else:']
            for s in self.else_body:
                for line in str(s).splitlines():
                    lines += ['    %s' % line]
        return '\n'.join(lines)

class WhileStatement(Expr):
    def __init__(self, cond, body):
        Expr.__init__(self)
        assert isinstance(body, list)
        self.cond = cond
        self.body = body

    def __repr__(self):
        lines = ['while %s:' % self.cond]
        for s in self.body:
            for line in str(s).splitlines():
                lines += ['    %s' % line]
        return '\n'.join(lines)

class ForStatement(Expr):
    def __init__(self, name, iter, body):
        Expr.__init__(self)
        self.name = name
        self.iter = iter
        self.body = body

    def __repr__(self):
        lines = ['for %s in %s:' % (self.name, self.iter)]
        for s in self.body:
            for line in str(s).splitlines():
                lines += ['    %s' % line]
        return '\n'.join(lines)

class ReturnStatement(Expr):
    def __init__(self, arg=None):
        Expr.__init__(self)
        if arg is None:
            self.arg = None
        else:
            self.arg = ExprLink(arg, self)

    def __repr__(self):
        if self.arg is None:
            return 'return'
        else:
            return 'return %s' % self.arg.pred

    def dead_code_elimination_allowed(self):
        return False

    def flatten(self, statements):
        if self.arg is not None:
            flatten_expr_link(self.arg, statements)

    def build_ssa(self, symbols):
        if self.arg is not None:
            self.arg.pred.build_ssa(symbols)

class AssertStatement(Expr):
    def __init__(self, arg):
        Expr.__init__(self)
        self.arg = ExprLink(arg, self)

    def __repr__(self):
        return 'assert %s' % self.arg.pred

    def dead_code_elimination_allowed(self):
        return False

    def flatten(self, statements):
        flatten_expr_link(self.arg, statements)

    def build_ssa(self, symbols):
        self.arg.pred.build_ssa(symbols)

class VerifyStatement(Expr):
    def __init__(self, arg):
        Expr.__init__(self)
        self.arg = ExprLink(arg, self)

    def __repr__(self):
        return 'verify %s' % self.arg.pred

    def dead_code_elimination_allowed(self):
        return False

    def flatten(self, statements):
        flatten_expr_link(self.arg, statements)

    def build_ssa(self, symbols):
        self.arg.pred.build_ssa(symbols)

class DefStatement(Expr):
    def __init__(self, name, args, body):
        Expr.__init__(self)
        self.name = name
        self.args = args
        self.body = body

    def __repr__(self):
        lines = ['def %s(%s):' % (self.name, ', '.join(self.args))]
        for s in self.body:
            for line in str(s).splitlines():
                lines += ['    %s' % line]
        return '\n'.join(lines)

class BasicBlock:
    def __init__(self):
        self.phis = []
        self.statements = []

def print_ir(basic_blocks):
    for block in basic_blocks:
        print('block:')
        for s in block.statements:
            print('  %s' % s)
    print()

def build_ssa(basic_blocks):
    # Identify all the local variable names in the function (anything used in a LHS context)
    # XXX Would be good to omit some or all $t variables
    symbol_names = set()
    for block in basic_blocks:
        for s in block.statements:
            if isinstance(s, AssignStatement):
                symbol_names.add(s.lhs.name)

    # Build up expression chains within each block
    for block in basic_blocks:
        symbols = {}
        if block == basic_blocks[0]: # In entry block, each local starts uninitialized
            for name in symbol_names:
                symbols[name] = CompileError("used uninitialized variable '%s'" % name)
        else: # In other blocks, each local starts as a phi
            for name in symbol_names:
                symbols[name] = Phi() # XXX phi arguments
        for (i, s) in enumerate(block.statements):
            s.build_ssa(symbols)
            if isinstance(s, AssignStatement):
                block.statements[i] = s.rhs.pred
                s.rhs.pred.uses.remove(s.rhs)

def dead_code_elimination(basic_blocks):
    for block in basic_blocks:
        # Iterate backwards over statements in each block, removing them as we go
        for i in reversed(range(len(block.statements))):
            s = block.statements[i]
            if (not s.uses and s.dead_code_elimination_allowed()) or s.is_atom():
                for link in s.operand_links():
                    link.pred.uses.remove(link)
                del block.statements[i]

def lower_ir(basic_blocks):
    for block in basic_blocks:
        block.statements = [s.lower() for s in block.statements]
        for s in block.statements:
            assert isinstance(s, FunctionCall) or isinstance(s, Argument) or isinstance(s, ReturnStatement), s # this is the only stuff that should remain

reg32_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']
reg64_names = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8',  'r9',  'r10',  'r11',  'r12',  'r13',  'r14',  'r15']

def get_reg_name(t, r):
    assert r >= 0
    if t == 'd':
        return reg32_names[r]
    elif t == 'q':
        return reg64_names[r]
    elif t == 'a':
        return '[%s]' % reg64_names[r]
    elif t == 'x':
        return 'xmm%d' % r
    elif t == 'y':
        return 'ymm%d' % r
    else:
        assert False, t

def BuiltinFunctionInfo(inst_name, dst_reg, src_regs):
    info = {'inst_name': inst_name, 'dst_reg': dst_reg, 'src_regs': src_regs}
    return info

builtin_functions = {
    'save_mxcsr': BuiltinFunctionInfo('stmxcsr [rsp-4]', '', ''),
    'restore_mxcsr': BuiltinFunctionInfo('ldmxcsr [rsp-4]', '', ''),
    'load_mxcsr': BuiltinFunctionInfo('ldmxcsr', '', 'a'),
    'store_mxcsr': BuiltinFunctionInfo('stmxcsr', '', 'a'),
    'vmovd_x_r': BuiltinFunctionInfo('vmovd', 'x', 'd'),
    'vmovd_r_x': BuiltinFunctionInfo('vmovd', 'd', 'x'),
    'vmovq_x_r': BuiltinFunctionInfo('vmovq', 'x', 'q'),
    'vmovq_r_x': BuiltinFunctionInfo('vmovq', 'q', 'x'),
    'vblendvps': BuiltinFunctionInfo('vblendvps', 'x', 'xxx'),
    'vbroadcast32i': BuiltinFunctionInfo('vbroadcastss', 'x', 'i'),
    'vcmpunordss': BuiltinFunctionInfo('vcmpunordss', 'x', 'xx'),
    'vfmaddsd': BuiltinFunctionInfo('vfmaddsd', 'x', 'xxx'),
    'vfmaddss': BuiltinFunctionInfo('vfmaddss', 'x', 'xxx'),
    'vmulss': BuiltinFunctionInfo('vmulss', 'x', 'xx'),
}

def my_token(tokens):
    try:
        t = next(tokens)
        return t
    except StopIteration:
        return None

def make_token(type, lineno):
    t = lex.LexToken()
    t.type = type
    t.value = None
    t.lineno = lineno
    t.lexpos = -1
    return t

def add_indents_dedents(tokens):
    indent_stack = [0]
    prev_type = ''
    require_indent = False
    for t in tokens:
        my_indent = indents[t.lineno-1]
        if require_indent:
            assert my_indent > indent_stack[-1]
            indent_stack.append(my_indent)
            yield make_token('INDENT', t.lineno)
            require_indent = False
        if t.type != 'NEWLINE':
            while my_indent < indent_stack[-1]:
                assert my_indent <= indent_stack[-2]
                indent_stack.pop()
                yield make_token('DEDENT', t.lineno)
        if prev_type == 'COLON':
            assert t.type == 'NEWLINE'
            require_indent = True
        if t.type != 'NEWLINE' or prev_type != 'NEWLINE': # filter multiple consecutive newlines
            yield t
        prev_type = t.type
    while len(indent_stack) > 1:
        indent_stack.pop()
        yield make_token('DEDENT', t.lineno)
    yield None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--windows', action='store_true')
    parser.add_argument('input_filename')
    parser.add_argument('output_filename')
    args = parser.parse_args()

    # Read and parse the input
    lex.lex()
    yacc.yacc()
    with open(args.input_filename) as f:
        data = f.read()
    lexer = lex.lexer
    tokens = iter(lexer.token, None)
    tokens = add_indents_dedents(tokens)
    global_statements = yacc.parse(data, lexer, tokenfunc=lambda: my_token(tokens))
    #for s in global_statements:
    #    print(s)
    #print()

    mem_int_literals = set()

    # Interpret the statements at global scope
    for global_s in global_statements:
        assert isinstance(global_s, DefStatement)

        # Add implicit argument assignments at start of function
        statements = [AssignStatement('=', Identifier(name), Argument(i)) for (i, name) in enumerate(global_s.args)] + global_s.body

        # Flatten expressions before creating blocks
        # XXX would be nice to eliminate most flattening
        new_statements = []
        for s in statements:
            s.flatten(new_statements)
            new_statements.append(s)
        statements = new_statements

        # Put statements in their respective basic blocks (easy for now, since we forbid all real control flow...)
        block = BasicBlock()
        block.statements = statements
        for (i, s) in enumerate(statements):
            assert not isinstance(s, IfStatement) # XXX
            assert not isinstance(s, WhileStatement) # XXX
            assert not isinstance(s, ForStatement) # XXX
            assert not isinstance(s, DefStatement) # XXX
            if i == len(statements) - 1:
                assert isinstance(s, ReturnStatement) # XXX last statement MUST be a return
            else:
                assert not isinstance(s, ReturnStatement) # XXX all other statements MUST NOT be a return
        basic_blocks = [block]

        # Convert to SSA form and clean up deadweight
        build_ssa(basic_blocks)
        dead_code_elimination(basic_blocks)

        # Lower from expressions to instructions
        lower_ir(basic_blocks)

        # Allocate registers
        # ABI reference docs:
        # https://msdn.microsoft.com/en-us/library/ms235286.aspx
        # http://www.x86-64.org/documentation/abi.pdf
        free_r_regs = set(range(16)) - {4} # remove RSP from list of usable regs
        free_x_regs = set(range(16))
        need_vzeroupper = False
        clobbered_r_regs = set()
        clobbered_x_regs = set()
        if args.windows:
            callee_saved_r_regs = [3, 5, 6, 7, 12, 13, 14, 15]
            callee_saved_x_regs = range(6, 16)
        else:
            callee_saved_r_regs = [3, 5, 12, 13, 14, 15]
            callee_saved_x_regs = []
        for block in basic_blocks:
            for s in block.statements:
                if isinstance(s, Argument):
                    if args.windows:
                        s.reg = [1, 2, 8, 9][s.index] # rcx, rdx, r8, r9
                    else:
                        s.reg = [7, 6, 2, 1, 8, 9][s.index] # rdi, rsi, rdx, rcx, r8, r9    
                    s.reg_type = 'r'
                    s.ref_count = len(s.uses)
                    assert s.ref_count > 0
                    free_r_regs.remove(s.reg)
                elif isinstance(s, FunctionCall):
                    builtin = builtin_functions[s.func.pred.name]
                    if 'need_vzeroupper' in builtin:
                        need_vzeroupper = True
                    for arg in s.args:
                        if isinstance(arg.pred, IntLiteral):
                            continue
                        if arg.pred.reg >= 0:
                            assert arg.pred.ref_count > 0
                            arg.pred.ref_count -= 1
                            if not arg.pred.ref_count:
                                if arg.pred.reg_type == 'r':
                                    free_r_regs.add(arg.pred.reg)
                                else:
                                    assert arg.pred.reg_type == 'x'
                                    free_x_regs.add(arg.pred.reg)
                    if builtin['dst_reg'] == '':
                        s.reg = -1
                    elif builtin['dst_reg'] == 'x':
                        if builtin['inst_name'] in {'vfmaddsd', 'vfmaddss'}:
                            # XXX should have more freedom about which register to clobber
                            # XXX should add a mov when necessary
                            assert s.args[1].pred.reg in free_x_regs
                            s.reg = s.args[1].pred.reg
                        else:
                            s.reg = min(free_x_regs)
                        s.reg_type = 'x'
                        s.ref_count = len(s.uses)
                        if s.ref_count > 0: # ref_count can be 0 -- if so, the register is not really in use
                            free_x_regs.remove(s.reg)
                        clobbered_x_regs.add(s.reg)
                    elif builtin['dst_reg'] in {'d', 'q'}:
                        s.reg = min(free_r_regs)
                        s.reg_type = 'r'
                        s.ref_count = len(s.uses)
                        if s.ref_count > 0: # ref_count can be 0 -- if so, the register is not really in use
                            free_r_regs.remove(s.reg)
                        clobbered_r_regs.add(s.reg)
                    else:
                        assert False, builtin['dst_reg']
                elif isinstance(s, ReturnStatement):
                    if s.arg is not None:
                        # Assert that the return value is already in rax
                        # XXX If it's not, need to move it to rax automatically
                        assert s.arg.pred.reg == 0
                        assert s.arg.pred.reg_type == 'r'
                else:
                    assert False, s

        fw = io.StringIO()
        for i in callee_saved_r_regs:
            if i in clobbered_r_regs:
                fw.write('    push %s\n' % reg64_names[i])
        for i in callee_saved_x_regs:
            assert i not in clobbered_x_regs # XXX not handled yet
        for block in basic_blocks:
            for s in block.statements:
                if isinstance(s, FunctionCall):
                    builtin = builtin_functions[s.func.pred.name]
                    if builtin['inst_name'] in {'vfmaddsd', 'vfmaddss'}:
                        assert s.reg == s.args[1].pred.reg
                        fw.write('    vfmadd213%s %s, %s, %s\n' % (builtin['inst_name'][-2:],
                            get_reg_name(builtin['dst_reg'], s.reg),
                            get_reg_name(builtin['src_regs'][i], s.args[0].pred.reg),
                            get_reg_name(builtin['src_regs'][i], s.args[2].pred.reg)))
                    elif builtin['dst_reg'] in {'d', 'q', 'x'}:
                        fw.write('    %s %s' % (builtin['inst_name'], get_reg_name(builtin['dst_reg'], s.reg)))
                        for (i, arg) in enumerate(s.args):
                            if isinstance(arg.pred, IntLiteral):
                                mem_int_literals.add(arg.pred.value)
                                fw.write(', [rel const_0x%X]' % arg.pred.value)
                            else:
                                fw.write(', %s' % get_reg_name(builtin['src_regs'][i], arg.pred.reg))
                        fw.write('\n')
                    elif builtin['dst_reg'] == '':
                        fw.write('    %s' % builtin['inst_name'])
                        if builtin['src_regs'] == '':
                            pass
                        else:
                            fw.write(' %s' % ', '.join(get_reg_name(builtin['src_regs'][i], arg.pred.reg) for (i, arg) in enumerate(s.args)))
                        fw.write('\n')
                    else:
                        assert False, builtin['dst_reg']
                elif isinstance(s, ReturnStatement):
                    if need_vzeroupper:
                        fw.write('    vzeroupper\n')
                    for i in reversed(callee_saved_r_regs):
                        if i in clobbered_r_regs:
                            fw.write('    pop %s\n' % reg64_names[i])
                    fw.write('    ret\n')
        global_s.asm_code = fw.getvalue()

    with open(args.output_filename, 'w') as f:
        for i in sorted(mem_int_literals):
            f.write('const_0x%X:\n' % i)
            f.write('    dd 0x%X\n' % i)
        f.write('\n')
        for global_s in global_statements:
            f.write('global %s\n' % global_s.name)
            f.write('%s:\n' % global_s.name)
            f.write(global_s.asm_code)
            f.write('\n')

if __name__ == '__main__':
    main()
