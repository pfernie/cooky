= Notes/Questions =
* usize v. u32
* String v. &str
* validate domain/path?
** makes sense for parse(), but via builder methods? Makes builder API less ergonomic (not so bad w/ ?)

* TODO: impl From<cookie::Cookie>, Into<cookie::Cookie>
* TODO: impl FromStr
// impl FromStr for Cookie {
//     type Err = Error;
//     fn from_str(s: &str) -> Result<Cookie, Error>
//     {
//         Cookie::parse(s)
//     }
// }

* TODO: CookieOven
// impl .bake() -> WarmCookie (String wrapper)
* TODO: enforce Domain (option?)
* TODO: enforce Path (option?)
* TODO: non-local domain checking (option?)
* TODO: custom attributes?
