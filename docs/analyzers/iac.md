# iac

`iac` reads the deployment templates a repository ships for its server:
Bicep (`.bicep`, `.bicepparam`), ARM JSON and Terraform (`.tf`, `.tfvars`).
It reports administrator and database passwords that a template fixes for
every deployment. Nothing is deployed. A tree with no such templates reports
the analyzer as `SKIPPED`.

## What it reads

**Secret properties.** It reads properties such as these:

- `administratorLoginPassword`, `adminPassword`, `password`;
- `administrator_password`, `admin_password`, `master_password`.

**Where the value comes from.** The analyzer follows parameters, variables
and Terraform `var.` / `local.` references, and sorts each value into one of
five kinds:

| Value | Kind |
|---|---|
| A string literal, or the default of a parameter or variable that is one; a literal in a parameters file or a committed `.tfvars` | fixed |
| `uniqueString(...)` or `guid(...)` over deployment values, alone or inside a string | predictable |
| `newGuid()`, Terraform `random_password` / `random_string` | generated |
| A `@secure()` parameter without a default; a parameter set by a parameters file or a module call; a Key Vault `getSecret`, `listKeys` or `reference` | supplied |
| Anything else | unknown, not reported |

**Network access.** It reads these from the same templates:

- firewall rules that admit every IPv4 address (`0.0.0.0` to
  `255.255.255.255`);
- firewall rules that admit all Azure addresses (`0.0.0.0` to `0.0.0.0`),
  which includes other customers' subscriptions;
- `publicly_accessible = true`;
- the private markers: `publicNetworkAccess: 'Disabled'`,
  `public_network_access_enabled = false` and a delegated subnet.

## Rules

| Rule | Fires when | Severity |
|---|---|---|
| `iac.hardcoded_secret` | The secret is fixed | HIGH and potential when the templates open the network; MEDIUM and needs_review otherwise |
| `iac.predictable_secret` | The secret is a deterministic hash | HIGH and potential when a hash input also appears in a resource name (and so in public host names) and the network is open; MEDIUM and needs_review otherwise |

A finding shows only the shape of a literal secret (`N******!`), never the
secret itself.

## Limitations

- **Bicep and Terraform are read line by line.** A value split over several
  lines, built in another module, or set in a loop is not followed.
- **A default can be overridden elsewhere.** Overrides from parameters files
  and module calls are seen. A default overridden in a pipeline variable or at
  an azd prompt is still reported.
- **Network access.** Network security groups, private endpoints defined
  elsewhere and policies are not read.
- **Other formats.** Pulumi, CDK, CloudFormation, Kubernetes and Compose are
  not read.
