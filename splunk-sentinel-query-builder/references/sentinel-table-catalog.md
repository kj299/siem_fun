# Sentinel / Log Analytics Table Catalog

## Use this file when

- writing or reviewing a KQL query and you need the real name of a table
- translating an SPL `index=` / `sourcetype=` scope into a Sentinel table scope
- you are about to name a table you have not seen in this file

This file is the provenance registry for Sentinel table names. The validator
checks every table-position identifier in a `kql` block against it, so a table
named in a query but absent here fails validation. That is deliberate: inventing
a table name is the KQL equivalent of inventing a sourcetype, and it fails at
query time with an empty result rather than an error.

**Table names are case-sensitive in KQL.** `SigninLogs` is correct;
`SignInLogs` is a different (non-existent) table and returns nothing.

## Adding a table

Only add a table you have confirmed in Microsoft's own documentation, and cite
the page. If you cannot confirm it, emit a discovery query instead:

```kql
search *
| distinct $table
| sort by $table asc
```

## Identity (Microsoft Entra ID)

| Table | Contents | Reference |
| --- | --- | --- |
| `SigninLogs` | Interactive user sign-ins, where a user supplied an authentication factor. Note the lowercase `i` in `in`. | [Entra ID connector data types](https://learn.microsoft.com/azure/sentinel/connect-azure-active-directory#microsoft-entra-id-data-connector-data-types) |
| `AADNonInteractiveUserSignInLogs` | Sign-ins performed by a client on behalf of a user with no user interaction. Note that this name does capitalise the `I`. | [Entra ID connector data types](https://learn.microsoft.com/azure/sentinel/connect-azure-active-directory#microsoft-entra-id-data-connector-data-types) |
| `AuditLogs` | Directory activity: user and group management, application and directory changes. | [Entra ID connector data types](https://learn.microsoft.com/azure/sentinel/connect-azure-active-directory#microsoft-entra-id-data-connector-data-types) |

## Azure platform and workspace operations

| Table | Contents | Reference |
| --- | --- | --- |
| `AzureActivity` | Azure subscription-level control-plane events. | [Data source schema reference](https://learn.microsoft.com/azure/sentinel/data-source-schema-reference) |
| `AzureDiagnostics` | Resource diagnostic logs, including Logic Apps actions behind a playbook. | [Data source schema reference](https://learn.microsoft.com/azure/sentinel/data-source-schema-reference) |
| `Usage` | Hourly ingestion volume per table. Key columns: `DataType`, `Quantity` (Mbytes), `IsBillable`, `Solution`. | [Usage table columns](https://learn.microsoft.com/azure/azure-monitor/reference/tables/usage#columns) |
| `Operation` | Daily records of data-allowance benefit used. | [Azure Monitor cost and usage](https://learn.microsoft.com/azure/azure-monitor/fundamentals/cost-usage#view-data-allocation-benefits) |
| `Heartbeat` | Agent check-in records; the usual basis for "is this source still reporting". | [Entity insights data sources](https://learn.microsoft.com/azure/sentinel/entity-pages#entity-insights) |

## Host and network

| Table | Contents | Reference |
| --- | --- | --- |
| `SecurityEvent` | Windows security event log. | [Entity insights data sources](https://learn.microsoft.com/azure/sentinel/entity-pages#entity-insights) |
| `Syslog` | Linux syslog. | [Data source schema reference](https://learn.microsoft.com/azure/sentinel/data-source-schema-reference) |
| `CommonSecurityLog` | CEF-formatted firewall, VPN, and web proxy events. | [UEBA data sources](https://learn.microsoft.com/azure/sentinel/ueba-reference#ueba-data-sources) |
| `W3CIISLog` | IIS web server logs. | [Data source schema reference](https://learn.microsoft.com/azure/sentinel/data-source-schema-reference) |
| `VMConnection` | VM Insights network connection records. | [Data source schema reference](https://learn.microsoft.com/azure/sentinel/data-source-schema-reference) |

## Office 365

| Table | Contents | Reference |
| --- | --- | --- |
| `OfficeActivity` | Office 365 management activity, including Exchange and SharePoint operations. | [Data source schema reference](https://learn.microsoft.com/azure/sentinel/data-source-schema-reference) |

## Sentinel operational

| Table | Contents | Reference |
| --- | --- | --- |
| `SentinelHealth` | Health events for connectors, analytics rules, automation rules, and playbooks. Not billable. | [Health and audit data storage](https://learn.microsoft.com/azure/sentinel/health-audit#health-and-audit-data-storage) |
| `SentinelAudit` | Audit events: rule create, update, delete. Billable. | [Health and audit data storage](https://learn.microsoft.com/azure/sentinel/health-audit#health-and-audit-data-storage) |
| `BehaviorAnalytics` | UEBA entity enrichment used by entity pages. | [Entity insights data sources](https://learn.microsoft.com/azure/sentinel/entity-pages#entity-insights) |

Prefer the prebuilt functions `_SentinelHealth()` and `_SentinelAudit()` over
querying those two tables directly. Microsoft maintains the functions across
schema changes, so a query built on them keeps working when the underlying
table changes.

These are **functions, not tables**, so they are not registered above and the
validator does not treat a query leading with one as a table reference. An
identifier followed by `(` is a call, wherever it appears.

## Microsoft Defender XDR (via the Defender XDR connector)

These stream into purpose-built tables only when the Defender XDR connector is
enabled. Confirm the connector is on before scoping a query to them.

| Table | Contents | Reference |
| --- | --- | --- |
| `DeviceProcessEvents` | Process creation and related endpoint events. | [DeviceProcessEvents table](https://learn.microsoft.com/azure/azure-monitor/reference/tables/deviceprocessevents) |
| `DeviceNetworkInfo` | Device network properties: adapters, IP and MAC addresses, connected networks. | [Advanced hunting schema tables](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables#learn-the-schema-tables) |
| `DeviceRegistryEvents` | Registry key and value creation and modification. | [Advanced hunting schema tables](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables#learn-the-schema-tables) |

## Placeholders

These are not real tables. They stand in for a name the user supplies, and the
validator accepts them in table position for that reason. Use one of these
rather than inventing a plausible-looking table name in an example.

| Placeholder | Use |
| --- | --- |
| `TableName` | any table, where the example is about the operator rather than the data |
| `YOUR_TABLE` | a table the user must name before the query can run |

## Discovering what a workspace actually has

Never guess when the workspace is reachable. List the tables that carry data:

```kql
Usage
| where TimeGenerated > ago(7d)
| summarize TotalGB = sum(Quantity) / 1024 by DataType
| sort by TotalGB desc
```

Inspect one table's schema before naming its columns:

```kql
TableName
| getschema
```
