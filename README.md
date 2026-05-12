# PHP Unserialize UAF PoC & RCE Exploit

Reproduction of two related `unserialize()` heap-use-after-free vulnerabilities in PHP, targeting **PHP 8.5.5** (current stable) and **PHP 7.2.1**. Both achieve arbitrary code execution via fake `zend_closure` construction.

## Vulnerabilities

| | var_destroy UAF | Calif UAF |
|---|---|---|
| **Root cause** | `var_destroy()` dtor walk runs without `BG(serialize_lock)` at L308 | `zend_user_unserialize()` missing `BG(serialize_lock)++` around method dispatch |
| **Trigger** | Duplicate array key + `__destruct` | `Serializable::unserialize()` re-entrant call |
| **Effect** | Phase 1 frees `var_entries` chunks; Phase 2 `__destruct` reads freed memory via `R:N` back-reference | Same UAF, different entry path through `Serializable` interface |
| **Original report** | dinosn (2026-05-02) | [Calif.io MAD Bugs](https://blog.calif.io/p/mad-bugs-finding-and-exploiting-a) (2026-05-01) |

Both vulnerabilities share the same UAF mechanism in `var_destroy` but have **independent root causes**. Calif's proposed fix does not fix the var_destroy triggers.

## Directory Structure

```
php_uaf/
├── 8.5.5/
│   ├── Dockerfile              # Non-ASAN build (for exploit)
│   ├── Dockerfile.asan         # ASAN build (for PoC)
│   ├── build.sh
│   ├── var_destroy_uaf/
│   │   ├── poc/poc.php
│   │   ├── exp/exploit.php
│   │   ├── run_poc.sh
│   │   ├── run_exp.sh
│   │   └── vuln-php/           # Key vulnerable source files
│   └── calif_uaf/
│       ├── poc/poc.php
│       ├── exp/exploit.php
│       ├── run_poc.sh
│       ├── run_exp.sh
│       └── vuln-php/
├── 7.2.1/
│   ├── Dockerfile              # Non-ASAN build (ubuntu:20.04)
│   ├── Dockerfile.asan         # ASAN build (ubuntu:20.04 + libasan5)
│   ├── build.sh
│   ├── var_destroy_uaf/
│   │   ├── poc/poc.php
│   │   ├── exp/exploit.php
│   │   ├── run_poc.sh
│   │   ├── run_exp.sh
│   │   └── vuln-php/
│   └── calif_uaf/
│       ├── poc/poc.php
│       ├── exp/exploit.php
│       ├── run_poc.sh
│       ├── run_exp.sh
│       └── vuln-php/
│   ├── writeup.md              # Version-specific writeup
│   └── ...
├── 7.2.1/
│   ├── ...
│   ├── writeup.md              # Version-specific writeup
```

## Quick Start

```bash
# Build Docker images
cd 8.5.5  # or 7.2.1
./build.sh

# Run PoC (ASAN — triggers heap-use-after-free)
./var_destroy_uaf/run_poc.sh
./calif_uaf/run_poc.sh

# Run exploit (non-ASAN — achieves RCE)
./var_destroy_uaf/run_exp.sh
./calif_uaf/run_exp.sh
```

## Exploit Technique

Both exploits use the same post-UAF strategy:

1. **Heap spray**: During `__destruct`, allocate strings sized to reclaim the freed `var_entries` chunks (8208 bytes on 7.2.1, 8160 bytes on 8.5.5). Fill them with the address of a fake `zend_closure`.
2. **Fake closure**: Construct a fake `zend_closure` object in a static PHP string, populated with addresses resolved dynamically by parsing the ELF symbol table via `/proc/self/exe`.
3. **R: back-reference**: `unserialize('R:1500;')` reads the sprayed fake zval pointer from the freed chunk. The result is a callable `zend_closure` whose `orig_internal_handler` points to `zif_system`.
4. **RCE**: Call the fake closure like a function: `$result('id')` → `system('id')`.

## Version Differences

| | PHP 8.5.5 | PHP 7.2.1 |
|---|---|---|
| Build base | ubuntu:24.04 | ubuntu:20.04 |
| `VAR_ENTRIES_MAX` | 1018 | 1024 |
| `var_entries` size | 8160 | 8208 |
| `func.handler` offset | obj+144 | obj+104 |
| `orig_internal_handler` offset | obj+336 | obj+304 |
| ASAN requires | configure with `-fsanitize=address` | configure with `-fsanitize=address` + `libasan5` + `LIBS=-ldl` |

## Status

No CVE assigned. PHP's policy since 2017 does not assign CVEs for `unserialize()` memory-corruption bugs.

## References

- [Calif.io — MAD Bugs: Finding and Exploiting a 21-Year-Old PHP Bug](https://blog.calif.io/p/mad-bugs-finding-and-exploiting-a)
- [dinosn — var_destroy reentrancy UAF](https://d1n0s3r.github.io/) (2026-05-02)
