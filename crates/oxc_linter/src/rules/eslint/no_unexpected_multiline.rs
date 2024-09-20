use memchr::memchr;
use oxc_ast::AstKind;
use oxc_diagnostics::OxcDiagnostic;
use oxc_macros::declare_oxc_lint;
use oxc_span::{GetSpan, Span};

use crate::{context::LintContext, rule::Rule, AstNode};

#[derive(Debug, Default, Clone)]
pub struct NoUnexpectedMultiline;

declare_oxc_lint!(
    /// ### What it does
    ///
    ///
    /// ### Why is this bad?
    ///
    ///
    /// ### Examples
    ///
    /// Examples of **incorrect** code for this rule:
    /// ```js
    /// FIXME: Tests will fail if examples are missing or syntactically incorrect.
    /// ```
    ///
    /// Examples of **correct** code for this rule:
    /// ```js
    /// FIXME: Tests will fail if examples are missing or syntactically incorrect.
    /// ```
    NoUnexpectedMultiline,
    suspicious,
    pending
);

impl Rule for NoUnexpectedMultiline {
    fn run<'a>(&self, node: &AstNode<'a>, ctx: &LintContext<'a>) {
        match node.kind() {
            AstKind::CallExpression(call_expr) => {
                if call_expr.optional {
                    return;
                }
                if let Some(AstKind::ChainExpression(_)) = ctx.nodes().parent_kind(node.id()) {
                    return;
                }
                let src =
                    ctx.source_range(Span::new(call_expr.callee.span().end, call_expr.span.end));
                if let Some(open_paren) = memchr(b'(', src.as_bytes()) {
                    if let Some(newline) = memchr(b'\n', src.as_bytes()) {
                        if newline < open_paren {
                            ctx.diagnostic(OxcDiagnostic::warn("Unexpected newline between function name and open parenthesis of function call").with_label(Span::new(open_paren as u32, (open_paren + 1) as u32)));
                        }
                    }
                }
            }
            AstKind::MemberExpression(member_expr) => {
                if !member_expr.is_computed() || member_expr.optional() {
                    return;
                }
                let src = ctx.source_range(Span::new(
                    member_expr.object().span().end,
                    member_expr.span().end,
                ));
                if let Some(open_bracket) = memchr(b'[', src.as_bytes()) {
                    if let Some(newline) = memchr(b'\n', src.as_bytes()) {
                        if newline < open_bracket {
                            ctx.diagnostic(OxcDiagnostic::warn("Unexpected newline between object and open bracket of property access").with_label(Span::new(open_bracket as u32, (open_bracket + 1) as u32)));
                        }
                    }
                }
            }
            AstKind::TaggedTemplateExpression(tagged_template_expr) => {
                let start = if let Some(generics) = &tagged_template_expr.type_parameters {
                    generics.span.end
                } else {
                    tagged_template_expr.tag.span().end
                };
                let src = ctx.source_range(Span::new(start, tagged_template_expr.span.end));
                if let Some(backtick) = memchr(b'`', src.as_bytes()) {
                    if let Some(newline) = memchr(b'\n', src.as_bytes()) {
                        if newline < backtick {
                            ctx.diagnostic(
                                OxcDiagnostic::warn(
                                    "Unexpected newline between template tag and template literal",
                                )
                                .with_label(Span::new(backtick as u32, (backtick + 1) as u32)),
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[test]
fn test() {
    use crate::tester::Tester;

    let pass = vec![
        "(x || y).aFunction()",
        "[a, b, c].forEach(doSomething)",
        "var a = b;\n(x || y).doSomething()",
        "var a = b\n;(x || y).doSomething()",
        "var a = b\nvoid (x || y).doSomething()",
        "var a = b;\n[1, 2, 3].forEach(console.log)",
        "var a = b\nvoid [1, 2, 3].forEach(console.log)",
        "\"abc\\\n(123)\"",
        "var a = (\n(123)\n)",
        "f(\n(x)\n)",
        "(\nfunction () {}\n)[1]",
        "let x = function() {};\n   `hello`", // { "ecmaVersion": 6 },
        "let x = function() {}\nx `hello`",   // { "ecmaVersion": 6 },
        "String.raw `Hi\n${2+3}!`;",          // { "ecmaVersion": 6 },
        "x\n.y\nz `Valid Test Case`",         // { "ecmaVersion": 6 },
        "f(x\n)`Valid Test Case`",            // { "ecmaVersion": 6 },
        "x.\ny `Valid Test Case`",            // { "ecmaVersion": 6 },
        "(x\n)`Valid Test Case`",             // { "ecmaVersion": 6 },
        "
			foo
			/ bar /2
		",
        "
			foo
			/ bar / mgy
		",
        "
			foo
			/ bar /
			gym
		",
        "
			foo
			/ bar
			/ ygm
		",
        "
			foo
			/ bar /GYM
		",
        "
			foo
			/ bar / baz
		",
        "foo /bar/g",
        "
			foo
			/denominator/
			2
		",
        "
			foo
			/ /abc/
		",
        "
			5 / (5
			/ 5)
		",
        "
			tag<generic>`
				multiline
			`;
		", // {                "parser": require("../../fixtures/parsers/typescript-parsers/tagged-template-with-generic/tagged-template-with-generic-1")            },
        "
			tag<
				generic
			>`
				multiline
			`;
		", // {                "parser": require("../../fixtures/parsers/typescript-parsers/tagged-template-with-generic/tagged-template-with-generic-2")            },
        "
			tag<
				generic
			>`multiline`;
		", // {                "parser": require("../../fixtures/parsers/typescript-parsers/tagged-template-with-generic/tagged-template-with-generic-3")            },
        "var a = b\n  ?.(x || y).doSomething()", // { "ecmaVersion": 2020 },
        "var a = b\n  ?.[a, b, c].forEach(doSomething)", // { "ecmaVersion": 2020 },
        "var a = b?.\n  (x || y).doSomething()", // { "ecmaVersion": 2020 },
        "var a = b?.\n  [a, b, c].forEach(doSomething)", // { "ecmaVersion": 2020 },
        "class C { field1\n[field2]; }",         // { "ecmaVersion": 2022 },
        "class C { field1\n*gen() {} }",         // { "ecmaVersion": 2022 },
        "class C { field1 = () => {}\n[field2]; }", // { "ecmaVersion": 2022 },
        "class C { field1 = () => {}\n*gen() {} }", // { "ecmaVersion": 2022 }
    ];

    let fail = vec![
        "var a = b\n(x || y).doSomething()",
        "var a = (a || b)\n(x || y).doSomething()",
        "var a = (a || b)\n(x).doSomething()",
        "var a = b\n[a, b, c].forEach(doSomething)",
        "var a = b\n    (x || y).doSomething()",
        "var a = b\n  [a, b, c].forEach(doSomething)",
        "let x = function() {}\n `hello`", // { "ecmaVersion": 6 },
        "let x = function() {}\nx\n`hello`", // { "ecmaVersion": 6 },
        "x\n.y\nz\n`Invalid Test Case`",   // { "ecmaVersion": 6 },
        "
			foo
			/ bar /gym
		",
        "
			foo
			/ bar /g
		",
        "
			foo
			/ bar /g.test(baz)
		",
        "
			foo
			/bar/gimuygimuygimuy.test(baz)
		",
        "
			foo
			/bar/s.test(baz)
		",
        "const x = aaaa<\n  test\n>/*\ntest\n*/`foo`", // {                "parser": require("../../fixtures/parsers/typescript-parsers/tagged-template-with-generic/tagged-template-with-generic-and-comment")            },
        "class C { field1 = obj\n[field2]; }",         // { "ecmaVersion": 2022 },
        "class C { field1 = function() {}\n[field2]; }", // { "ecmaVersion": 2022 }
    ];

    Tester::new(NoUnexpectedMultiline::NAME, pass, fail).test_and_snapshot();
}
