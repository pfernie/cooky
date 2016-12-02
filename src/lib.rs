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

    pub fn set_domain(&mut self, domain: &str) -> &mut Self {
        let domain = domain.trim();
        self.domain_end = match self.domain_value_start() {
            Some(s) => {
                if 0 != domain.len() {
                    self.serialization.truncate(s);
                    self.serialization.push_str(domain);
                    Some(self.serialization.len())
                } else {
                    self.serialization.truncate(self.value_end);
                    None
                }
            }
            None if 0 == domain.len() => None,
            None => {
                self.serialization.push_str("; Domain=");
                self.serialization.push_str(domain);
                Some(self.serialization.len())
            }
        };
        self
    }

    pub fn path(&self) -> Option<&str> {
        self.path_end.and_then(|e| self.path_value_start().map(|s| self.slice(s..e)))
    }

    pub fn set_path(&mut self, path: &str) -> &mut Self {
        let path = path.trim();
        self.path_end = match self.path_value_start() {
            Some(s) => {
                if 0 != path.len() {
                    self.serialization.truncate(s);
                    self.serialization.push_str(path);
                    Some(self.serialization.len())
                } else {
                    self.serialization.truncate(self.value_end);
                    None
                }
            }
            None if 0 == path.len() => None,
            None => {
                self.serialization.push_str("; Path=");
                self.serialization.push_str(path);
                Some(self.serialization.len())
            }
        };
        self
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
        self.path_end.map(|_| self.value_end + "; Path=".len())
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
