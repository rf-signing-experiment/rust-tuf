//! Matching target paths against the patterns that delegations use to describe which targets they
//! are trusted for. See the [`PATHPATTERN`] definition in the TUF specification.
//!
//! [`PATHPATTERN`]: https://theupdateframework.github.io/specification/v1.0.36/#pathpattern

/// Whether `path` matches `pattern`, in which `*` matches any sequence of characters, including
/// the empty one, `?` matches any one character, and every other character matches itself.
///
/// Wildcards never match a `/`, so `*.tgz` matches `foo.tgz` but not `targets/foo.tgz`.
pub(crate) fn matches(pattern: &str, path: &str) -> bool {
    let patterns = pattern.split('/');
    let components = path.split('/');

    patterns.clone().count() == components.clone().count()
        && patterns
            .zip(components)
            .all(|(pattern, component)| component_matches(pattern, component))
}

/// Whether `component` matches `pattern`, neither of which contains a `/`.
fn component_matches(pattern: &str, component: &str) -> bool {
    let pattern = pattern.chars().collect::<Vec<_>>();
    let component = component.chars().collect::<Vec<_>>();

    // Match greedily, and when stuck, backtrack to let the most recent `*` match one more
    // character. Only the most recent `*` ever needs revisiting, which keeps this to
    // O(pattern * component) without recursion.
    let (mut p, mut c) = (0, 0);
    let mut backtrack = None;
    while c < component.len() {
        match pattern.get(p) {
            Some('*') => {
                p += 1;
                backtrack = Some((p, c));
            }
            Some(&expected) if expected == '?' || expected == component[c] => {
                p += 1;
                c += 1;
            }
            _ => {
                let Some((star_p, star_c)) = backtrack else {
                    return false;
                };
                p = star_p;
                c = star_c + 1;
                backtrack = Some((p, c));
            }
        }
    }

    pattern[p..].iter().all(|&rest| rest == '*')
}

#[cfg(test)]
mod test {
    use super::*;

    fn check(pattern: &str, matching: &[&str], not_matching: &[&str]) {
        for path in matching {
            assert!(matches(pattern, path), "{pattern:?} should match {path:?}");
        }
        for path in not_matching {
            assert!(
                !matches(pattern, path),
                "{pattern:?} should not match {path:?}"
            );
        }
    }

    // The examples from the PATHPATTERN definition in the spec.
    #[test]
    fn spec_examples() {
        check(
            "targets/*.tgz",
            &["targets/foo.tgz", "targets/bar.tgz"],
            &["targets/foo.txt"],
        );
        check(
            "foo-version-?.tgz",
            &["foo-version-2.tgz", "foo-version-a.tgz"],
            &["foo-version-alpha.tgz"],
        );
        check("*.tgz", &["foo.tgz", "bar.tgz"], &["targets/foo.tgz"]);
        check(
            "foo.tgz",
            &["foo.tgz"],
            &["bar.tgz", "foo.tgz/bar", "foo/foo.tgz"],
        );
    }

    #[test]
    fn wildcards_do_not_match_separators() {
        check("*", &["foo"], &["foo/bar", "foo/", "/foo"]);
        check("?", &["a"], &["/"]);
        check("foo/*", &["foo/bar", "foo/"], &["foo", "foo/bar/baz"]);
        check("*/*", &["foo/bar", "a/b"], &["foo", "foo/bar/baz"]);
        check(
            "foo/*/baz",
            &["foo/bar/baz"],
            &["foo/baz", "foo/bar/qux/baz"],
        );
        check("**", &["", "foo"], &["foo/bar"]);
    }

    #[test]
    fn not_a_prefix() {
        check("foo", &["foo"], &["foo/bar", "foobar"]);
        check("foo/", &["foo/"], &["foo", "foo/bar"]);
    }

    #[test]
    fn star() {
        check("foo*", &["foo", "foobar"], &["fo", "barfoo"]);
        check("*foo", &["foo", "barfoo"], &["foobar"]);
        check("f*o", &["fo", "foo", "fooooo", "fxo"], &["f", "foa"]);
        check(
            "*.tar.gz",
            &["foo.tar.gz", ".tar.gz", "foo.tar.tar.gz"],
            &["foo.tar.gzip", "foo.tgz"],
        );
        check("*a*b", &["ab", "xaybzb", "aab"], &["aba", "ba"]);
        check(
            "a*b*c",
            &["abc", "abcbc", "axbxc", "abbc"],
            &["acb", "abcx"],
        );
    }

    #[test]
    fn question_mark() {
        check("?", &["a", "?", "*"], &["", "ab"]);
        check("??", &["ab"], &["a", "abc"]);
        check("a?c", &["abc", "a?c"], &["ac", "abbc"]);
        check("?*", &["a", "abc"], &[""]);
    }

    #[test]
    fn other_glob_syntax_is_literal() {
        check("[ab]", &["[ab]"], &["a", "b"]);
        check("[!a]", &["[!a]"], &["b"]);
        check("{a,b}", &["{a,b}"], &["a", "b"]);
        check("\\*", &["\\", "\\foo"], &["*"]);
    }

    #[test]
    fn case_sensitive() {
        check("FOO", &["FOO"], &["foo", "Foo"]);
    }

    #[test]
    fn unicode() {
        check("?", &["é", "日"], &["e\u{301}"]);
        check("日*語", &["日本語"], &["日本"]);
    }

    // Patterns come from metadata, so ones crafted to be slow mustn't be.
    #[test]
    fn pathological_patterns_are_fast() {
        let path = "a".repeat(10_000);
        assert!(matches(&"*a".repeat(100), &path));
        assert!(!matches(&format!("{}b", "*a".repeat(100)), &path));
    }
}
