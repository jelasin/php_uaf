# PHP 8.5.5 — `zend_user_unserialize` Missing `serialize_lock` UAF

> Reproduction of the vulnerability from [Calif.io MAD Bugs](https://blog.calif.io/p/mad-bugs-finding-and-exploiting-a) (2026-05-01).
> Sister bug to the dinosn `var_destroy` reentrancy UAF (see `../var_destroy_uaf/`).

**Author:** Calif.io (PoC by reproduction)
**Date:** 2026-05-11
**Affected:** PHP 8.5.5 (current stable). Present since PHP 5.1 (~21 years).
**Status:** No CVE — PHP policy since 2017 does not assign CVEs for `unserialize()` memory-corruption bugs.

## TL;DR

`zend_user_unserialize()` in `Zend/zend_interfaces.c` (L450-452) calls `zend_call_method_with_1_params()` to dispatch `Serializable::unserialize()` **without** incrementing `BG(serialize_lock)`. When the PHP-level `unserialize()` method calls PHP's `unserialize()` function, `php_var_unserialize_init()` sees `lock == 0 && level > 0` and **reuses** the outer call's `var_hash`. The inner call shares the same back-reference table and dtor chain. Objects created by the inner call end up in the shared dtor chain. When the outer call's `var_destroy()` runs, Phase 1 frees extension chunks, then Phase 2's `i_zval_ptr_dtor` (L308) triggers `__destruct` without the lock. Inside `__destruct`, `unserialize('R:N;')` reuses the var_hash → `var_access(N)` follows the dangling `entries.next` → **heap-use-after-free**.

## Vulnerable Code Path

File: `Zend/zend_interfaces.c`, function `zend_user_unserialize` (L441-461):

```c
ZEND_API int zend_user_unserialize(zval *object, zend_class_entry *ce,
    const unsigned char *buf, size_t buf_len, zend_unserialize_data *data)
{
    zval zdata;
    if (UNEXPECTED(object_init_ex(object, ce) != SUCCESS)) {
        return FAILURE;
    }
    ZVAL_STRINGL(&zdata, (char*)buf, buf_len);
    zend_call_method_with_1_params(        // <-- NO BG(serialize_lock)++ here!
        Z_OBJ_P(object), Z_OBJCE_P(object), NULL, "unserialize", NULL, &zdata);
    zval_ptr_dtor(&zdata);
    if (EG(exception)) { return FAILURE; } else { return SUCCESS; }
}
```

Reentry flow:
1. Outer `unserialize()` processes `C:4:"Evil":1:{x}` → calls `object_custom()`
2. `object_custom()` → `ce->unserialize()` → `zend_user_unserialize()` (no lock)
3. `Evil::unserialize()` calls PHP `unserialize()` → reuses outer `var_hash`
4. Inner call creates Trigger object, duplicate key pushes it to shared dtor chain
5. Inner completes (level>1, no `var_destroy`)
6. Outer completes → `var_destroy()`:
   - Phase 1 (L242-246): `efree` all extension chunks — `entries.next` dangling
   - Phase 2 (L248-313): walks dtor chain, `i_zval_ptr_dtor(zv)` at L308
   - Trigger `__destruct` fires (no lock) → `unserialize('R:1500;')`
   - `var_access(1500)` follows dangling `entries.next` → **UAF**

## Relationship to var_destroy UAF (dinosn)

Both vulnerabilities share the same UAF mechanism in `var_destroy` (Phase 1 frees chunks, Phase 2 accesses them), but have **independent root causes**:

| | Calif (this PoC) | DinOSn (`var_destroy_uaf/`) |
|---|---|---|
| **Root cause** | Missing lock in `zend_user_unserialize` | Missing lock at L284/L302/L308 in `var_destroy` |
| **Entry point** | `Serializable::unserialize()` via `C:` format | Duplicate array keys, `__wakeup` return values |
| **Object injection** | Inner `unserialize()` from `Evil::unserialize()` | Direct payload manipulation |
| **Fix** | Add lock to `zend_user_unserialize` | Hold lock over entire dtor walk |

Calif's proposed fix (lock around `zend_call_method_with_1_params`) blocks this entry point but does **not** fix the dinosn triggers. DinOSn's proposed fix (lock over entire `var_destroy` dtor walk) blocks both.

## Directory Structure

```
calif_uaf/
├── Dockerfile            # Build ASAN-enabled PHP 8.5.5
├── build.sh              # Build script
├── run_poc.sh            # Run all PoCs
├── poc/
│   ├── poc_serializable.php  # PoC 1: Full trace with Serializable
│   ├── poc_direct.php        # PoC 2: Minimal trigger
│   └── poc_leak.php          # PoC 3: Heap spray + controlled deref
├── vuln-php/
│   ├── ext/standard/
│   │   ├── var_unserializer.re   # var_destroy, var_access, php_var_unserialize_init
│   │   └── var.c                 # unserialize() entry point
│   └── Zend/
│       ├── zend_interfaces.c     # Vulnerable: missing serialize_lock (L450-452)
│       └── zend_objects.c        # __destruct dispatch (L172)
└── docs/
    └── patch_zend_interfaces.py  # Calif's proposed fix
```

## Reproduction

### Build (or reuse existing `php-uaf` image)
```bash
./build.sh
# Or reuse: docker run --rm -v "$PWD:/work" php-uaf /php-src/sapi/cli/php ...
```

### Run PoCs
```bash
./run_poc.sh
```

Or individually:
```bash
# PoC 1 — Full trace
docker run --rm -v "$PWD:/work" php-uaf-calif \
    /php-src/sapi/cli/php /work/poc/poc_serializable.php 2>&1

# PoC 2 — Minimal
docker run --rm -v "$PWD:/work" php-uaf-calif \
    /php-src/sapi/cli/php /work/poc/poc_direct.php 2>&1

# PoC 3 — Heap spray
docker run --rm -e ASAN_OPTIONS='abort_on_error=1:halt_on_error=1:quarantine_size_mb=0:detect_leaks=0' \
    -v "$PWD:/work" php-uaf-calif \
    /php-src/sapi/cli/php /work/poc/poc_leak.php 2>&1
```

### Expected Output

All three PoCs trigger ASAN `heap-use-after-free`. PoC 3 demonstrates controlled pointer dereference (SEGV at `0x4141414141414141`).

## Proposed Fix

Add `BG(serialize_lock)` around the method dispatch in `zend_user_unserialize`:

```diff
 ZEND_API int zend_user_unserialize(zval *object, zend_class_entry *ce,
     const unsigned char *buf, size_t buf_len, zend_unserialize_data *data)
 {
     zval zdata;

     if (UNEXPECTED(object_init_ex(object, ce) != SUCCESS)) {
         return FAILURE;
     }

     ZVAL_STRINGL(&zdata, (char*)buf, buf_len);
+    BG(serialize_lock)++;
     zend_call_method_with_1_params(
         Z_OBJ_P(object), Z_OBJCE_P(object), NULL, "unserialize", NULL, &zdata);
+    BG(serialize_lock)--;
     zval_ptr_dtor(&zdata);

     if (EG(exception)) { return FAILURE; } else { return SUCCESS; }
 }
```

Note: This fix blocks the Calif entry point only. For complete coverage, also apply the `var_destroy` lock fix (see `../var_destroy_uaf/README.md`).
