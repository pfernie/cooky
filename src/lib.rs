#[macro_use]
extern crate lazy_static;
extern crate time;

use std::ops::{Range, RangeFrom, RangeTo};

use time::Tm;

lazy_static! {
    static ref EARLIEST_TM: Tm = time::strptime("1900-01-01T00:00:00Z", "%Y-%m-%dT%H:%M:%SZ")
            .unwrap();
}

const DOMAIN_PREFIX: &'static str = "; Domain=";
const PATH_PREFIX: &'static str = "; Path=";
const MAX_AGE_PREFIX: &'static str = "; Max-Age=";
const SECURE_ATTR: &'static str = "; Secure";
const HTTPONLY_ATTR: &'static str = "; HttpOnly";
const EXPIRES_PREFIX: &'static str = "; Expires=";

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

// FIXME: CookieOven
// impl .bake() -> WarmCookie (String wrapper)
// TODO: enforce Domain (option?)
// TODO: enforce Path (option?)
// TODO: non-local domain checking (option?)
// TODO: custom attributes?
pub struct Cookie {
    serialization: String,
    name_end: usize,
    value_end: usize,
    // although ordering of these attributes is not defined in the RFC,
    // we enforce the ordering is Domain, Path, Secure, HttpOnly, Expires
    // during serialization. specifically, Secure, HttpOnly, and Expires
    // are at the end of the serialization as they are all of a known fixed size
    // when present, with Expires last to simplify replacing its value
    domain_end: Option<usize>,
    path_end: Option<usize>,
    max_age: Option<(u64, usize)>,
    secure: bool,
    httponly: bool,
    expires: Option<Tm>,
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
            max_age: None,
            secure: false,
            httponly: false,
            expires: None,
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

        self.name_end = new_name_end;
        adjust(&mut self.value_end, old_name_end, new_name_end);
        if let Some(ref mut index) = self.domain_end {
            adjust(index, old_name_end, new_name_end);
        }
        if let Some(ref mut index) = self.path_end {
            adjust(index, old_name_end, new_name_end);
        }
        if let Some((_, ref mut index)) = self.max_age {
            adjust(index, old_name_end, new_name_end);
        }

        name.push_str(self.slice(old_name_end..));
        self.serialization = name;
        self
    }

    pub fn value(&self) -> &str {
        self.slice(self.value_start()..self.value_end)
    }

    #[inline]
    fn value_start(&self) -> usize {
        self.name_end + "=".len()
    }

    pub fn set_value(&mut self, value: &str) -> &mut Self {
        let value = value.trim();
        let old_value_end = self.value_end;
        let suffix = {
            let s = self.slice(old_value_end..);
            if 0 == s.len() {
                None
            } else {
                Some(s.to_owned())
            }
        };

        let new_value_end = {
            let value_start = self.value_start();
            self.serialization.truncate(value_start);
            self.serialization.push_str(value);
            self.serialization.len()
        };

        if let Some(ref s) = suffix {
            self.serialization.push_str(s);
        }

        self.value_end = new_value_end;
        if let Some(ref mut index) = self.domain_end {
            adjust(index, old_value_end, new_value_end);
        }
        if let Some(ref mut index) = self.path_end {
            adjust(index, old_value_end, new_value_end);
        }
        if let Some((_, ref mut index)) = self.max_age {
            adjust(index, old_value_end, new_value_end);
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
    fn domain_value_start(&self) -> Option<usize> {
        self.domain_end.map(|_| self.value_end + DOMAIN_PREFIX.len())
    }

    #[inline]
    fn domain_end_or_prior(&self) -> usize {
        self.domain_end.unwrap_or_else(|| self.value_end)
    }

    pub fn set_domain(&mut self, domain: &str) -> &mut Self {
        let domain = domain.trim();
        let old_domain_end = self.domain_end_or_prior();

        let new_domain_end = {
            let old_value_start = self.domain_value_start();
            let old_value_end = self.domain_end;
            let preceding_end = self.value_end;
            let (new_domain_end, suffix) = self.set_attr_value(DOMAIN_PREFIX,
                                                               domain,
                                                               old_value_start,
                                                               old_value_end,
                                                               preceding_end);

            if let Some(ref suffix) = suffix {
                self.serialization.push_str(suffix);
            }

            new_domain_end
        };

        self.domain_end = new_domain_end;
        let new_domain_end = self.domain_end_or_prior();
        if let Some(ref mut index) = self.path_end {
            adjust(index, old_domain_end, new_domain_end);
        }
        if let Some((_, ref mut index)) = self.max_age {
            adjust(index, old_domain_end, new_domain_end);
        }

        self
    }

    pub fn path(&self) -> Option<&str> {
        self.path_end.and_then(|e| self.path_value_start().map(|s| self.slice(s..e)))
    }

    #[inline]
    fn path_value_start(&self) -> Option<usize> {
        self.path_end.map(|_| self.domain_end_or_prior() + PATH_PREFIX.len())
    }

    #[inline]
    fn path_end_or_prior(&self) -> usize {
        self.path_end.unwrap_or_else(|| self.domain_end_or_prior())
    }

    pub fn set_path(&mut self, path: &str) -> &mut Self {
        let path = path.trim();
        let old_path_end = self.path_end_or_prior();
        let new_path_end = {
            let old_value_start = self.path_value_start();
            let old_value_end = self.path_end;
            let preceding_end = self.domain_end_or_prior();
            let (new_path_end, suffix) = self.set_attr_value(PATH_PREFIX,
                                                             path,
                                                             old_value_start,
                                                             old_value_end,
                                                             preceding_end);

            if let Some(ref suffix) = suffix {
                self.serialization.push_str(suffix);
            }

            new_path_end
        };

        self.path_end = new_path_end;
        let new_path_end = self.path_end_or_prior();
        if let Some((_, ref mut index)) = self.max_age {
            adjust(index, old_path_end, new_path_end);
        }
        self
    }

    pub fn max_age(&self) -> Option<u64> {
        self.max_age.map(|(a, _)| a)
    }

    pub fn max_age_str(&self) -> Option<&str> {
        self.max_age.and_then(|(_, e)| self.max_age_value_start().map(|s| self.slice(s..e)))
    }

    #[inline]
    fn max_age_end_or_prior(&self) -> usize {
        self.max_age.map(|(_, e)| e).unwrap_or_else(|| self.path_end_or_prior())
    }

    #[inline]
    fn max_age_value_start(&self) -> Option<usize> {
        self.max_age.map(|_| self.path_end_or_prior() + MAX_AGE_PREFIX.len())
    }

    pub fn set_max_age(&mut self, max_age: u64) -> &mut Self {
        if self.max_age.map(|(v, _)| v).unwrap_or(0) == max_age {
            return self;
        }

        let max_age_end = if 0 == max_age {
            let s = self.path_end_or_prior();
            let e = self.max_age.map(|(_, e)| e).unwrap();
            self.serialization.drain(s..e);
            None
        } else {
            let suffix = if let Some((_, e)) = self.max_age {
                let s = self.max_age_value_start().unwrap();
                self.truncate_and_take(s, e);
                None
            } else {
                let e = self.path_end_or_prior();
                let suffix = self.take(e);
                self.serialization.push_str(MAX_AGE_PREFIX);
                suffix
            };

            self.serialization.push_str(&format!("{}", max_age));
            let max_age_end = self.serialization.len();
            if let Some(ref s) = suffix {
                self.serialization.push_str(s);
            }

            Some(max_age_end)
        };

        self.max_age = max_age_end.map(|e| (max_age, e));
        self
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    #[inline]
    fn secure_end_or_prior(&self) -> usize {
        self.max_age_end_or_prior() + if self.secure { SECURE_ATTR.len() } else { 0 }
    }

    pub fn set_secure(&mut self, secure: bool) -> &mut Self {
        if self.secure != secure {
            let preceding_end = self.max_age_end_or_prior();
            let old_secure = self.secure;
            self.set_flag_str(preceding_end, SECURE_ATTR, old_secure, secure);
            self.secure = secure;
        }
        self
    }

    pub fn httponly(&self) -> bool {
        self.httponly
    }

    #[inline]
    fn httponly_end_or_prior(&self) -> usize {
        self.secure_end_or_prior() +
        if self.httponly {
            HTTPONLY_ATTR.len()
        } else {
            0
        }
    }

    pub fn set_httponly(&mut self, httponly: bool) -> &mut Self {
        if self.httponly != httponly {
            let preceding_end = self.secure_end_or_prior();
            let old_httponly = self.httponly;
            self.set_flag_str(preceding_end, HTTPONLY_ATTR, old_httponly, httponly);
            self.httponly = httponly;
        }
        self
    }

    pub fn expires(&self) -> Option<Tm> {
        self.expires
    }

    pub fn expires_str(&self) -> Option<&str> {
        self.expires.and_then(|_| self.expires_value_start().map(|s| self.slice(s..)))
    }

    #[inline]
    fn expires_value_start(&self) -> Option<usize> {
        self.expires.map(|_| self.httponly_end_or_prior() + EXPIRES_PREFIX.len())
    }

    pub fn expire(&mut self) -> &mut Self {
        self.set_expires(Some(*EARLIEST_TM))
    }

    pub fn set_expires(&mut self, expires: Option<Tm>) -> &mut Self {
        if self.expires.is_none() && expires.is_none() {
            return self;
        }
        let expires_utc = expires.map(|e| e.to_utc());
        if self.expires == expires_utc {
            return self;
        }

        match expires_utc {
            None => {
                let trunc_from = self.httponly_end_or_prior();
                self.serialization.truncate(trunc_from);
            }
            Some(expires_utc) => {
                if self.expires.is_none() {
                    self.serialization.push_str(EXPIRES_PREFIX);
                } else {
                    let trunc_from = self.httponly_end_or_prior() + EXPIRES_PREFIX.len();
                    self.serialization.truncate(trunc_from);
                }
                self.serialization.push_str(&format!("{}", expires_utc.rfc822()));
            }
        }

        self.expires = expires;
        self
    }

    #[inline]
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
                let suffix = self.truncate_and_take(old_value_start, old_value_end.unwrap());
                self.serialization.push_str(new_value);
                (Some(self.serialization.len()), suffix)
            }
            None if 0 == new_value.len() => (None, None),
            None => {
                let suffix = self.take(preceding_end);
                self.serialization.push_str(attr_name);
                self.serialization.push_str(new_value);
                (Some(self.serialization.len()), suffix)
            }
        }
    }

    #[inline]
    fn set_flag_str(&mut self,
                    preceding_end: usize,
                    flag_str: &str,
                    old_value: bool,
                    new_value: bool) {
        let suffix = {
            let slice_from = preceding_end + if !old_value { 0 } else { flag_str.len() };
            let s = self.slice(slice_from..);
            if 0 == s.len() {
                None
            } else {
                Some(s.to_owned())
            }
        };
        self.serialization.truncate(preceding_end);
        if new_value {
            self.serialization.push_str(flag_str);
        }
        if let Some(ref s) = suffix {
            self.serialization.push_str(s);
        }
    }

    #[inline]
    fn slice<R>(&self, range: R) -> &str
        where R: RangeArg
    {
        range.slice_of(&self.serialization)
    }

    #[inline]
    fn truncate_and_take(&mut self, truncate_from: usize, take_from: usize) -> Option<String> {
        let taken = {
            let s = self.slice(take_from..);
            if 0 == s.len() {
                None
            } else {
                Some(s.to_owned())
            }
        };
        self.serialization.truncate(truncate_from);
        taken
    }

    #[inline]
    fn take(&mut self, from: usize) -> Option<String> {
        self.truncate_and_take(from, from)
    }

    #[inline]
    pub fn into_string(self) -> String {
        self.serialization
    }
}

#[inline]
fn adjust(index: &mut usize, old: usize, new: usize) {
    *index -= old;
    *index += new;
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
    use time;
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

        c.set_domain("www.example.com");
        c.set_secure(true);

        c.set_value("booz");
        assert_eq!(c.value(), "booz");
        assert_eq!(c.cookie_pair(), ("foo", "booz"));
        assert_eq!(c.as_str(), "foo=booz; Domain=www.example.com; Secure");
        c.set_value("  bar  ");
        assert_eq!(c.value(), "bar");
        assert_eq!(c.cookie_pair(), ("foo", "bar"));
        assert_eq!(c.as_str(), "foo=bar; Domain=www.example.com; Secure");

        c.set_domain("");
        c.set_secure(false);

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

        assert_eq!(c.max_age(), None);
        c.set_max_age(1234);
        assert_eq!(c.max_age(), Some(1234));
        assert_eq!(c.max_age_str(), Some("1234"));
        assert_eq!(c.as_str(), "foo=bar; Max-Age=1234");
        c.set_max_age(0);
        assert_eq!(c.max_age(), None);
        assert_eq!(c.max_age_str(), None);
        assert_eq!(c.as_str(), "foo=bar");
        c.set_secure(true);
        c.set_max_age(1234);
        assert_eq!(c.max_age(), Some(1234));
        assert_eq!(c.max_age_str(), Some("1234"));
        assert_eq!(c.as_str(), "foo=bar; Max-Age=1234; Secure");
        c.set_max_age(0);
        assert_eq!(c.max_age(), None);
        assert_eq!(c.max_age_str(), None);
        assert_eq!(c.as_str(), "foo=bar; Secure");
        c.set_secure(false);

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
    fn test_expires() {
        let expires = "Thu, 22 Mar 2012 14:53:18 GMT";
        let tm = time::strptime(expires, "%a, %d %b %Y %T GMT").unwrap();
        let mut c = Cookie::new("foo", "bar");
        assert_eq!(c.as_str(), "foo=bar");
        assert_eq!(c.expires(), None);
        c.set_expires(Some(tm));
        assert_eq!(c.as_str(), "foo=bar; Expires=Thu, 22 Mar 2012 14:53:18 GMT");
        assert_eq!(c.expires(), Some(tm));
        assert_eq!(c.expires_str(), Some(expires));
        c.set_expires(None);
        assert_eq!(c.as_str(), "foo=bar");
        assert_eq!(c.expires(), None);
        c.set_expires(Some(tm));
        c.set_domain("www.example.com");
        assert_eq!(c.as_str(),
                   "foo=bar; Domain=www.example.com; Expires=Thu, 22 Mar 2012 14:53:18 GMT");
        c.set_expires(None);
        assert_eq!(c.as_str(), "foo=bar; Domain=www.example.com");
        c.expire();
        assert_eq!(c.as_str(),
                   "foo=bar; Domain=www.example.com; Expires=Sun, 01 Jan 1900 00:00:00 GMT");
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
