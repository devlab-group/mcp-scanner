# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**. Do not open a public
issue, pull request or discussion for a security problem.

Include:

- the output of `mcp-scanner --version`, or the commit you built from;
- the command line or API request, and the configuration file if one was used;
- the smallest target that reproduces the problem: a snapshot, a source tree,
  a package name and version, or an archive;
- the result you got and the result you expected.

You should get a first response within a week. Fixes go into the default
branch and the next release; older releases do not get backported fixes.

## What counts as a vulnerability

The scanner reads hostile input by design, so a flaw in the scanner is often a
security problem for the person running it. Report any of these privately:

- A scan reports `SAFE` although a required analyzer failed, timed out, or
  skipped content without recording a coverage gap.
- Content in a scanned target decides what gets analyzed, for example a file
  that excludes itself by its name or contents.
- Any control in the threat model's
  [threats to the scanner](docs/threat-model.md#part-two-threats-to-the-scanner)
  table does not hold: code runs during a static scan, an archive or symlink
  escapes the scan root, the scanner connects to a private address it should
  refuse, an API key or token reaches a log or a report, scanned content gets
  tools or actions through the model analyzer, or a sandboxed run escapes its
  container or sees host secrets.
- An HTTP API caller reaches a target kind, probe level or tool call that the
  deployment's configuration does not permit.

## What does not

These are documented limits. Open a regular issue if you think one should
change:

- vulnerabilities in a scanned MCP server itself; report those to its
  maintainers;
- a detection an analyzer does not claim to make. `mcp-scanner analyzers
  --details` lists what each analyzer detects and where it is blind;
- behaviour the [threat model](docs/threat-model.md) states is not defended,
  such as a `stdio` scan running the target on the host with the operator's
  privileges, or a kernel-level container escape.
