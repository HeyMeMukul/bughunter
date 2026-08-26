# Common Duplicate Reasons — Why Reports Get Closed

## Top 10 Duplicate Reasons

1. **Nuclei/Scanner template hit** — If nuclei finds it, 10 other hunters already reported it
2. **CVE on publicly disclosed technology** — Known CVEs are automated gold for everyone
3. **Exposed .git directory** — The first thing every hunter checks
4. **GraphQL introspection enabled** — Standard discovery, reported within hours
5. **Missing rate limiting** — Everyone tests this, 50+ duplicates per program
6. **Open S3 bucket with no PII** — Common finding, low payout, heavily reported
7. **Spring Boot actuator endpoints** — `/actuator/health` is the most duplicated finding
8. **phpinfo() exposed** — Trivially discoverable
9. **Directory listing enabled** — Checked by every scanner
10. **CORS misconfiguration without credentials** — "CORS with *" is reported daily

## How to Avoid Duplicates

1. **Check the program's known issues** — Most programs list known/acknowledged findings
2. **Go deeper than scanners** — Nuclei finds the surface. You find the logic.
3. **Chain, don't isolate** — Open redirect alone = duplicate. Open redirect → SSRF = unique.
4. **Test NEW features** — First-week features have zero reporters
5. **Test on uncommon ports** — Everyone tests :443. Nobody tests :8080/:8443/:3000.
6. **Focus on business logic** — Scanners can't test for "free shipping when quantity < 0"
7. **Look at acquisitions** — Companies that just acquired another company = new attack surface
8. **API versioning abuse** — v1 has auth, v2 has auth, v3-beta doesn't = unique finding
