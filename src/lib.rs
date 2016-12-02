use std::ops::{Range, RangeFrom, RangeTo};

trait RangeArg {
    fn slice_of<'a>(&self, s: &'a str) -> &'a str;
}

impl RangeArg for Range<usize> {
    #[inline]
    fn slice_of<'a>(&self, s: &'a str) -> &'a str {
        &s[self.start..self.end]
    }
}

impl RangeArg for RangeFrom<usize> {
    #[inline]
    fn slice_of<'a>(&self, s: &'a str) -> &'a str {
        &s[self.start..]
    }
}

impl RangeArg for RangeTo<usize> {
    #[inline]
    fn slice_of<'a>(&self, s: &'a str) -> &'a str {
        &s[..self.end]
    }
}

pub struct Cookie {
    serialization: String,
    name_end: usize,
    value_end: usize,
    // although ordering of these attributes is not defined in the RFC,
    // we will enforce the ordering is Domain, Path, Secure, HttpOnly
    // during parsing/serialization
    domain_end: Option<usize>,
    path_end: Option<usize>,
    secure: bool,
    httponly: bool,
}

impl Cookie {
    pub fn new(name: &str, value: &str) -> Cookie {
        let name = name.trim();
        let value = value.trim();
        let s = format!("{}={}", name, value);
        let value_end = s.len();
        Cookie {
            serialization: s,
            name_end: name.len(),
            value_end: value_end,
            domain_end: None,
            path_end: None,
            secure: false,
            httponly: false,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.serialization
    }

    pub fn name(&self) -> &str {
        self.slice(..self.name_end)
    }

    pub fn set_name(&mut self, name: &str) -> &mut Self {
        let mut name = name.trim().to_owned();
        let old_name_end = self.name_end;
        let new_name_end = name.len();

        let adjust = |index: &mut usize| {
            *index -= old_name_end;
            *index += new_name_end;
        };
        self.name_end = new_name_end;
        adjust(&mut self.value_end);
        if let Some(ref mut index) = self.domain_end {
            adjust(index);
        }
        if let Some(ref mut index) = self.path_end {
            adjust(index);
        }

        name.push_str(self.slice(old_name_end..));
        self.serialization = name;
        self
    }

    pub fn value(&self) -> &str {
        self.slice(self.value_start()..self.value_end)
    }

    pub fn set_value(&mut self, value: &str) -> &mut Self {
        let value = value.trim();
        let old_value_end = self.value_end;
        let suffix = match (self.domain_attr_start(), self.path_attr_start()) {
            (None, None) => None,
            (Some(i), _) => Some(self.slice(i..).to_owned()),
            (None, Some(i)) => Some(self.slice(i..).to_owned()),
        };
        self.serialization.truncate(self.name_end + "=".len());
        self.serialization.push_str(value);
        let new_value_end = self.serialization.len();
        if let Some(s) = suffix {
            self.serialization.push_str(&s);
        }

        let adjust = |index: &mut usize| {
            *index -= old_value_end;
            *index -= new_value_end;
        };
        self.value_end = new_value_end;
        if let Some(ref mut index) = self.domain_end {
            adjust(index);
        }
        if let Some(ref mut index) = self.path_end {
            adjust(index);
        }

        self
    }

    pub fn cookie_pair(&self) -> (&str, &str) {
        (self.slice(..self.name_end), self.slice(self.value_start()..self.value_end))
    }

    pub fn domain(&self) -> Option<&str> {
        self.domain_end.and_then(|e| self.domain_value_start().map(|s| self.slice(s..e)))
    }

    #[inline]
    fn domain_end_or_prior(&self) -> usize {
        self.domain_end.unwrap_or(self.value_end)
    }

    pub fn set_domain(&mut self, domain: &str) -> &mut Self {
        let domain = domain.trim();
        let old_domain_end = self.domain_end_or_prior();

        let (new_domain_end, suffix) = {
            let old_value_start = self.domain_value_start();
            let old_value_end = self.domain_end;
            let preceding_end = self.value_end;
            self.set_attr_value("Domain",
                                domain,
                                old_value_start,
                                old_value_end,
                                preceding_end)
        };

        if let Some(ref suffix) = suffix {
            self.serialization.push_str(suffix);
        }

        self.domain_end = new_domain_end;
        if let Some(ref mut index) = self.path_end {
            *index -= old_domain_end;
            *index += new_domain_end.unwrap_or(self.value_end);
        }
        self
    }

    pub fn path(&self) -> Option<&str> {
        self.path_end.and_then(|e| self.path_value_start().map(|s| self.slice(s..e)))
    }

    #[inline]
    fn path_end_or_prior(&self) -> usize {
        self.path_end.unwrap_or_else(|| self.domain_end_or_prior())
    }

    pub fn set_path(&mut self, path: &str) -> &mut Self {
        let path = path.trim();
        let (new_path_end, suffix) = {
            let old_value_start = self.path_value_start();
            let old_value_end = self.path_end;
            let preceding_end = self.domain_end_or_prior();
            self.set_attr_value("Path", path, old_value_start, old_value_end, preceding_end)
        };

        if let Some(ref suffix) = suffix {
            self.serialization.push_str(suffix);
        }

        self.path_end = new_path_end;
        self
    }

    fn set_attr_value(&mut self,
                      attr_name: &str,
                      new_value: &str,
                      old_value_start: Option<usize>,
                      old_value_end: Option<usize>,
                      preceding_end: usize)
                      -> (Option<usize>, Option<String>) {
        match old_value_start {
            Some(_) if 0 == new_value.len() => {
                self.serialization.drain(preceding_end..old_value_end.unwrap());
                (None, None)
            }
            Some(old_value_start) => {
                let suffix = Some(self.slice(old_value_end.unwrap()..).to_owned());
                self.serialization.truncate(old_value_start);
                self.serialization.push_str(new_value);
                (Some(self.serialization.len()), suffix)
            }
            None if 0 == new_value.len() => (None, None),
            None => {
                let suffix = Some(self.slice(preceding_end..).to_owned());
                self.serialization.truncate(preceding_end);
                self.serialization.push_str("; ");
                self.serialization.push_str(attr_name);
                self.serialization.push_str("=");
                self.serialization.push_str(new_value);
                (Some(self.serialization.len()), suffix)
            }
        }
    }

    pub fn set_secure(&mut self, secure: bool) -> &mut Self {
        if self.secure != secure {
            let end = self.domain_path_end();
            self.serialization.truncate(end);
            match (secure, self.httponly) {
                (true, true) => {
                    self.serialization.push_str("; Secure; HttpOnly");
                }
                (true, false) => {
                    self.serialization.push_str("; Secure");
                }
                (false, true) => {
                    self.serialization.push_str("; HttpOnly");
                }
                (false, false) => {}
            }
            self.secure = secure;
        }
        self
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    pub fn httponly(&self) -> bool {
        self.httponly
    }

    pub fn set_httponly(&mut self, httponly: bool) -> &mut Self {
        if self.httponly != httponly {
            if httponly {
                self.serialization.push_str("; HttpOnly");
            } else {
                let new_end = self.secure_end().unwrap_or_else(|| self.domain_path_end());
                self.serialization.truncate(new_end);
            }
            self.httponly = httponly;
        }
        self
    }

    #[inline]
    fn value_start(&self) -> usize {
        self.name_end + "=".len()
    }

    #[inline]
    fn domain_attr_start(&self) -> Option<usize> {
        self.domain_end.map(|_| self.value_end + "; ".len())
    }

    #[inline]
    fn domain_value_start(&self) -> Option<usize> {
        self.domain_end.map(|_| self.value_end + "; Domain=".len())
    }

    #[inline]
    fn path_attr_start(&self) -> Option<usize> {
        self.path_end.map(|_| self.domain_end.unwrap_or(self.value_end) + "; ".len())
    }

    #[inline]
    fn path_value_start(&self) -> Option<usize> {
        self.path_end.map(|_| self.domain_end.unwrap_or(self.value_end) + "; Path=".len())
    }

    #[inline]
    fn domain_path_end(&self) -> usize {
        match (self.domain_end, self.path_end) {
            (None, None) => self.value_end,
            (_, Some(e)) | (Some(e), _) => e,
        }
    }

    #[inline]
    fn secure_start(&self) -> Option<usize> {
        if !self.secure {
            None
        } else {
            Some(self.domain_path_end() + "; ".len())
        }
    }

    #[inline]
    fn secure_end(&self) -> Option<usize> {
        self.secure_start().map(|s| s + "Secure".len())
    }

    #[inline]
    fn slice<R>(&self, range: R) -> &str
        where R: RangeArg
    {
        range.slice_of(&self.serialization)
    }

    #[inline]
    pub fn into_string(self) -> String {
        self.serialization
    }
}

// TODO: impl From<cookie::Cookie>, Into<cookie::Cookie>
//
// TODO: impl FromStr
// impl FromStr for Cookie {
//     type Err = Error;
//     fn from_str(s: &str) -> Result<Cookie, Error>
//     {
//         Cookie::parse(s)
//     }
// }

#[cfg(test)]
mod tests {
    use super::Cookie;
    #[test]
    fn test_fields() {
        let mut c = Cookie::new("foo", "bar");
        assert_eq!(c.name(), "foo");
        assert_eq!(c.value(), "bar");
        assert_eq!(c.cookie_pair(), ("foo", "bar"));
        assert_eq!(c.as_str(), "foo=bar");

        c.set_name("quux".into());
        assert_eq!(c.name(), "quux");
        assert_eq!(c.value(), "bar");
        assert_eq!(c.cookie_pair(), ("quux", "bar"));
        assert_eq!(c.as_str(), "quux=bar");
        c.set_name("  foo  ".into());
        assert_eq!(c.name(), "foo");
        assert_eq!(c.value(), "bar");
        assert_eq!(c.cookie_pair(), ("foo", "bar"));
        assert_eq!(c.as_str(), "foo=bar");

        c.set_value("booz");
        assert_eq!(c.value(), "booz");
        assert_eq!(c.cookie_pair(), ("foo", "booz"));
        assert_eq!(c.as_str(), "foo=booz");
        c.set_value("  bar  ");
        assert_eq!(c.value(), "bar");
        assert_eq!(c.cookie_pair(), ("foo", "bar"));
        assert_eq!(c.as_str(), "foo=bar");

        assert_eq!(c.domain(), None);
        c.set_domain("www.example.com");
        assert_eq!(c.domain(), Some("www.example.com"));
        assert_eq!(c.as_str(), "foo=bar; Domain=www.example.com");
        c.set_domain(" foo.example.com ");
        assert_eq!(c.domain(), Some("foo.example.com"));
        assert_eq!(c.as_str(), "foo=bar; Domain=foo.example.com");
        c.set_domain("");
        assert_eq!(c.domain(), None);
        assert_eq!(c.as_str(), "foo=bar");
        c.set_domain(" foo.example.com ");
        assert_eq!(c.domain(), Some("foo.example.com"));
        c.set_domain("  ");
        assert_eq!(c.domain(), None);
        assert_eq!(c.as_str(), "foo=bar");

        assert_eq!(c.path(), None);
        c.set_path("/foo/bus/bar");
        assert_eq!(c.path(), Some("/foo/bus/bar"));
        assert_eq!(c.as_str(), "foo=bar; Path=/foo/bus/bar");
        c.set_path(" /moo/buz/baz ");
        assert_eq!(c.path(), Some("/moo/buz/baz"));
        assert_eq!(c.as_str(), "foo=bar; Path=/moo/buz/baz");
        c.set_path("");
        assert_eq!(c.path(), None);
        assert_eq!(c.as_str(), "foo=bar");
        c.set_path(" /moo/buz/baz ");
        assert_eq!(c.path(), Some("/moo/buz/baz"));
        c.set_path("  ");
        assert_eq!(c.path(), None);
        assert_eq!(c.as_str(), "foo=bar");

        c.set_domain("www.example.com");
        assert_eq!(c.domain(), Some("www.example.com"));
        assert_eq!(c.path(), None);
        assert_eq!(c.as_str(), "foo=bar; Domain=www.example.com");
        c.set_path("/foo/bus/bar");
        assert_eq!(c.domain(), Some("www.example.com"));
        assert_eq!(c.path(), Some("/foo/bus/bar"));
        assert_eq!(c.as_str(),
                   "foo=bar; Domain=www.example.com; Path=/foo/bus/bar");
        c.set_domain("");
        assert_eq!(c.domain(), None);
        assert_eq!(c.path(), Some("/foo/bus/bar"));
        assert_eq!(c.as_str(), "foo=bar; Path=/foo/bus/bar");
        c.set_domain("www.example.com");
        assert_eq!(c.domain(), Some("www.example.com"));
        assert_eq!(c.path(), Some("/foo/bus/bar"));
        assert_eq!(c.as_str(),
                   "foo=bar; Domain=www.example.com; Path=/foo/bus/bar");

        c.set_domain("");
        assert_eq!(c.domain(), None);
        c.set_domain("www.example.com");
        c.set_domain("  ");
        assert_eq!(c.domain(), None);
        c.set_path("");
        assert_eq!(c.path(), None);
        c.set_path("/foo/bus/bar");
        c.set_path("  ");
        assert_eq!(c.path(), None);

        assert_eq!(c.secure(), false);
        c.set_secure(true);
        assert_eq!(c.secure(), true);
        assert_eq!(c.as_str(), "foo=bar; Secure");
        c.set_secure(false);
        assert_eq!(c.secure(), false);
        assert_eq!(c.as_str(), "foo=bar");

        assert_eq!(c.httponly(), false);
        c.set_httponly(true);
        assert_eq!(c.httponly(), true);
        assert_eq!(c.as_str(), "foo=bar; HttpOnly");
        c.set_httponly(false);
        assert_eq!(c.httponly(), false);
        assert_eq!(c.as_str(), "foo=bar");

        c.set_secure(true);
        c.set_httponly(true);
        assert_eq!(c.as_str(), "foo=bar; Secure; HttpOnly");
        c.set_secure(false);
        assert_eq!(c.as_str(), "foo=bar; HttpOnly");
        c.set_secure(true);
        c.set_httponly(false);
        assert_eq!(c.as_str(), "foo=bar; Secure");
        c.set_secure(false);
        assert_eq!(c.as_str(), "foo=bar");
    }

    #[test]
    fn test_ws_trim() {
        let c = Cookie::new("  foo", "  bar");
        assert_eq!(c.name(), "foo");
        assert_eq!(c.value(), "bar");
        let c = Cookie::new("foo  ", "bar  ");
        assert_eq!(c.name(), "foo");
        assert_eq!(c.value(), "bar");
        let c = Cookie::new("  foo  ", "  bar  ");
        assert_eq!(c.name(), "foo");
        assert_eq!(c.value(), "bar");
    }
}
