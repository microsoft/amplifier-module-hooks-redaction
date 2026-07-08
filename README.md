# amplifier-module-hooks-redaction

An Amplifier redaction hook, plus the standalone `redaction` library it wraps.

This repository follows a two-tier "hook at repo root + shared library in a
subdirectory" layout (mirroring the `amplifier-bundle-context-intelligence`
pattern). The hook stays at the repo root — exactly where the ecosystem
already points — so existing consumers see zero change to its install path,
entry point, or package name. The reusable core lives in `modules/redaction/`.

```
amplifier-module-hooks-redaction/    (repo root == the Amplifier hook)
├── amplifier_module_hooks_redaction/   # the hook package (mount + glue)
├── tests/                              # hook-integration tests
└── modules/
    └── redaction/                      # the standalone "redaction" library
        ├── redaction/                  # zero-Amplifier-dependency core
        └── tests/                      # unit tests for the library
```

## The Amplifier hook (repo root)

`amplifier-module-hooks-redaction` (package `amplifier_module_hooks_redaction`,
entry point `hooks-redaction`) is a thin Amplifier hook that wires
`mask_text`/`scrub` into the Amplifier event pipeline. It masks secrets/PII in
event data before logging, and re-exports the `redaction` public API for
backward compatibility with existing consumers.

It is installed the same way it always was:

```bash
pip install "amplifier-module-hooks-redaction @ git+https://github.com/microsoft/amplifier-module-hooks-redaction@main"
```

The hook depends on the shared library via a git `#subdirectory` reference:

```
redaction @ git+https://github.com/microsoft/amplifier-module-hooks-redaction@main#subdirectory=modules/redaction
```

[!IMPORTANT]
Register with higher priority than logging.

## The `redaction` library (`modules/redaction/`)

`redaction` is a pure-stdlib (`re`, `typing`, `collections.abc`) library with
**zero Amplifier dependencies**. Consumer applications that only need the
masking primitives — not the Amplifier hook plumbing — should depend on this
package directly rather than vendoring a private copy or pulling in
`amplifier_core`.

Public API:

- `mask_text(text: str, rules=DEFAULT_RULES) -> str` — mask secrets/PII in a
  single string.
- `scrub(obj, rules=DEFAULT_RULES, allowlist=DEFAULT_ALLOWLIST, path="") -> Any`
  — recursively mask an arbitrary JSON-like structure (dict/list/scalar),
  honoring an allowlist of dotted paths that must survive untouched.
- `SECRET_PATTERNS`, `PII_PATTERNS`, `DEFAULT_ALLOWLIST`, `DEFAULT_RULES` —
  the underlying pattern/allowlist/rule constants.

Install it directly from the subdirectory:

```bash
pip install "redaction @ git+https://github.com/microsoft/amplifier-module-hooks-redaction@main#subdirectory=modules/redaction"
```

then:

```python
import redaction

redaction.mask_text("my key is AKIAIOSFODNN7EXAMPLE")
```

## Contributing

> [!NOTE]
> This project is not currently accepting external contributions, but we're actively working toward opening this up. We value community input and look forward to collaborating in the future. For now, feel free to fork and experiment!

Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
