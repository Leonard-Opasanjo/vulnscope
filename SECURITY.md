# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/Leonard-Opasanjo/vulnscope/security/advisories/new>.
Describe what you did, what happened, and how to reproduce it. You should hear back within seven days.

## In scope

- A scanned site being able to execute code, read files, or alter the database on the machine running
  VulnScope through its responses (headers, bodies, certificates, redirects).
- A way to make VulnScope send requests that are not in the documented passive set, or to a host the user did
  not name (for example through a redirect).
- Cross-site scripting or injection in the dashboard or in the HTML report through scanned content or notes.
- Findings being hidden or scores being wrong because of crafted responses.

## Out of scope

- The dashboard having no authentication. It is a local tool bound to `127.0.0.1`; exposing it is a deployment
  decision documented in the README.
- Checks that VulnScope does not perform. It is passive and shallow by design; missing a class of vulnerability
  is a feature request.
- The practice target's planted weaknesses.

## Responsible use

Only scan systems you own or have written permission to test. The tool requires you to confirm this on every
scan, but it cannot verify it. The author takes no responsibility for scans of third-party systems.
