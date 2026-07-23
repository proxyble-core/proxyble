You are helping me create multiple software in this workspace. 

git is setup.


## Proxyble prompt routing

Read only what you need.

- Wizard UI and management CLI: `src/*.go`
- Rule enforcement agent: `proxyble-rule-agent/`
- Product packaging, installed paths, and compatibility contracts: `PRODUCT-LAYOUT.md`
- Architecture and behavioral design: `DESIGN.md`

## Coding Guidelines

 - Be conservative, avoid writing too much extra code. If a bug requires a small fix, avoid adding extra validation fuctions for verifying an issue that might never occur again after the bug is fixed. Proxyble is complex and code bloat can get out of control real quick. Keep coding focused on the immediate task and nothing more. No rabbit holes. No tangents.
 - Every function must have a self-explanatory name and comment explaining briefly what it does.
 - Algorithms that are not self-explanatory must also be commented.
 - For proxyble, every wizard UI capability must also be available in command-line path with arguments, to enable automated or scripted deployments.