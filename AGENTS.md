You are helping me create multiple software in this workspace. 

git is setup.


## Proxyble prompt routing

Read only what you need.

- Wizard UI and management CLI: `src/*.go`
- Rule enforcement agent: `proxyble-rule-agent/`
- Product packaging, installed paths, and compatibility contracts: `PRODUCT-LAYOUT.md`
- Architecture and behavioral design: `DESIGN.md`

## Coding Guidelines

- Make the smallest coherent change that fully delivers the requested behavior, whether the work is a bug fix, new feature, behavior change, or maintenance task. Preserve existing architecture, APIs, and unrelated behavior unless the issue explicitly requires otherwise.
- Keep the diff narrowly scoped. Do not add speculative abstractions, generalized frameworks, defensive runtime validation, new dependencies, unrelated refactors, or support for hypothetical future requirements.
- Match validation and tests to the risk and scope of the requested change. For bug fixes, add focused regression coverage when the failure is nontrivial or likely to recur; do not add tests for trivial one-off corrections when existing coverage is sufficient. For new features, cover the core behavior and important edge cases. Do not create exhaustive test matrices unless the issue genuinely affects every variant or shared behavior cannot otherwise be verified.
- Reuse existing patterns and code paths. Add a helper or abstraction only when it is necessary for the requested change or removes meaningful duplication introduced by it.
- Prefer small, focused functions with self-explanatory names. Document exported declarations and any non-obvious intent, invariants, algorithms, edge cases, or tradeoffs. Do not add comments that merely repeat what the code does.
- Every new wizard UI capability must also be available through command-line arguments for automated deployments. Both interfaces should share the same underlying implementation rather than duplicate business logic.
