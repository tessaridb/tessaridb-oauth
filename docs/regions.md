# Regions

How tenants are kept in their home region and requests for them are sent there.


Each region is its own TessariDB deployment, and a company's identity data stays in its home region's store. At start
a server records its `PUBLIC_URL` in its region's directory, beside the region's companies. A server given `PEERS`
reads every other region's directory every five seconds and answers a request for a company another region serves
with `307 Temporary Redirect` to the same path and query at that region's `PUBLIC_URL`, so the method and body are
sent again there. A region that does not answer keeps the companies it last named; a company no region serves is
`404`. The admin console is not redirected.

The account a server reads another region with is declared in that region's store, reaching its directory only:

```text
DEFINE USER oauth_peer ON oauth_us.directory ROLE viewer PASSWORD '<password>';
```
