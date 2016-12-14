= cooky =

A simple Cookie implementation that stores components in a single string serialization, providing
access to components via slicing operations.

* Eagerly serializes/resizes as fields are set
* Does not allow for "custom" AttrVal items. Per [RFC 6265](https://tools.ietf.org/html/rfc6265#page-19):
```
   6.  Process the attribute-name and attribute-value according to the
       requirements in the following subsections.  (Notice that
       attributes with unrecognized attribute-names are ignored.)
```
