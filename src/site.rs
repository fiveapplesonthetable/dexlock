//! Parsing and filtering of contention source sites.
//!
//! A source site is a `File.ext:line` string taken from a monitor-contention
//! record (the line a thread was blocked or blocking on). Only sites that name a
//! real source line are resolvable; synthetic frames and unsymbolized frames are
//! skipped.

/// Split a `File.java:1234` site into `(file, line)`, or `None` when it is not a
/// resolvable source location:
/// - no numeric line component,
/// - an empty file component,
/// - a synthetic/lambda frame (contains `<`, e.g. `<lambda>`), which has no
///   stable source line to resolve against.
pub fn parse(site: &str) -> Option<(&str, i64)> {
    let s = site.trim();
    if s.is_empty() || s.contains('<') {
        return None;
    }
    let (file, line) = s.rsplit_once(':')?;
    let line: i64 = line.trim().parse().ok()?;
    if file.is_empty() {
        return None;
    }
    Some((file, line))
}

/// Whether a site is worth handing to the resolver.
pub fn is_resolvable(site: &str) -> bool {
    parse(site).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_real_sites() {
        assert_eq!(parse("Foo.java:12"), Some(("Foo.java", 12)));
        assert_eq!(
            parse("com/example/pkg/Foo.java:9"),
            Some(("com/example/pkg/Foo.java", 9))
        );
    }

    #[test]
    fn rejects_non_sites() {
        assert!(parse("Foo.java").is_none()); // no line
        assert!(parse("Foo.java:abc").is_none()); // non-numeric
        assert!(parse(":12").is_none()); // no file
        assert!(parse("Foo.java:<lambda>:3").is_none()); // synthetic frame
        assert!(parse("").is_none());
    }
}
