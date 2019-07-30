# Policy Urchin
Policy Urchin is a suite of tools for auditing who has access to resources in your AWS account. It is especially useful if you use a single AWS account that contains all human-used IAM users, who then assume roles into many different AWS accounts. Policy Urchin consists of three main commands:

### Refresh
Refresh builds a cache file representing IAM users which can assume roles into other AWS accounts. This command should be run when you want future simulations to include IAM users in other accounts.

### Simulate
Simulate determines what is capable of performing specified actions on specified resources. By default, it only examines IAM users in the same account that you are simulating resources in. If simulate is supplied with a cache file built by the Refresh command, it will also include IAM users in another account. Optionally, the simulation can also report on EC2 instances, ECS tasks, or Lambda functions which have permissions to perform the specified action. 

### Users
Users attempts to discover who or what is using an IAM User. The command examines CloudTrail and analyzes events performed by the specified IAM user. It will collect unique IP addresses and user agents and report them in an output file.

## Refresh
Policy Urchin's Simulate command is capable of analyzing users from two accounts at once. The intended use is to examine both users in the same account as the target resources and users in an SSO account. To examine users in an external (eg. SSO) account, you must first build a cache file containing information about IAM resoures in the account. To do so, run a command like `./policy-urchin refresh`. This command will use your default credentials, which should be for your SSO account. Once the command is finished, you should see a file in your working directory called cache/cache.json. This file will be used by the Simulate command until it is refreshed again. If refresh is run again in the same working directory, the cache file will be overwritten with current information.

## Simulate
Simulate is the main, most powerful command in Policy Urchin. It determines which roles and users can perform a given AWS action. It takes in a YAML or JSON configuration file as input, and produces the results in YAML format. Going forward, the configuration file will be referred to as the "audit file".

### Flags
| Flag Name | Short | Type | Required? | Description |
|-----------|-------|------|-----------|-------------|
| --audit-file | -a | string | Yes | Path to the audit file |
| --cache-file | -c | string | No | Path to cache file |
| --ec2 | -e | bool | No | Output ec2 instances with access |
| --ecs | -E | bool | No | Output ecs tasks with access |
| --lambda | -f | bool | No | Output lambda functions with access |
| --log-file | -l | string | No | Path to log file to write |
| --log-level | -L | string | No | Info, debug, error, or warn |
| --output | -o | string | No | Path to output file. Outputs to stdout if not specified |

### The Audit File
The audit file is how you tell Policy Urchin what you would like it to evaluate. The top level field of the file should be called "audits". Within "audits", specify one or more audit objects to be evaluated. Each audit object can contain the following fields:

| Field | Type | Required? | Description |
|-------|------|---|---------------|
| id | string | Yes | Human readable name for the audit |
| description | string | No | Describe what the audit evaluates. Not used by the program. |
| actions | string list | Yes | AWS API actions |
| resources | string list | No | ARNs of resources to test against |

Each audit will evaluate each action and resource and report each action-resource combination separately.

### The Output File
The output file is how Policy Urchin reports the results of its audits. If the "-o" flag is not specified, Policy urchin will write its output file to stdout. The output file will be structured like YAML, though its fields will be dependant on the audits run. Each audit will have a corresponding top-level field in the output. The field will have a name corresponding to the "id" of the audit. Then, each audit will have sub-fields for each "action" in the audit, and each action will have sub-fields for each "resource". Under each "resource" will be the results of the simulation. Each entry under the resource represents a single user, role, ec2 instance, etc. Each user that shows up under a resource has permission to perform the specified action on that resource.
