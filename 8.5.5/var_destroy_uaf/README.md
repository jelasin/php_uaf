# PHP 8.5.5 — `var_destroy` `__destruct` Reentrancy UAF

> Sister bug to [Calif.io MAD Bugs](https://blog.calif.io/p/mad-bugs-finding-and-exploiting-a) (2026-05-01).
> Independent root cause; survives the fix Calif proposes for `zend_user_unserialize`.

**Author:** dinosn
**Date:** 2026-05-02
**Affected:** PHP 8.5.5 (current stable). Pattern likely present back through PHP 8.0 / 7.x.
**Status:** No CVE — PHP policy since 2017 does not assign CVEs for `unserialize()` memory-corruption bugs.

## TL;DR

`var_destroy()` in `ext/standard/var_unserializer.re` walks the dtor list with `BG(serialize_lock)` bumped only around the *explicit* `__wakeup` and `__unserialize` user-code dispatches. Three *implicit* dispatch sites in the same loop run *without* the lock. Any of these can fire user `__destruct()` while `BG(unserialize).level > 0` and `BG(serialize_lock) == 0`. An inner `unserialize()` from inside that `__destruct` then re-uses the outer's `var_hash` — but `var_destroy` has *already* `efree`'d the back-reference array's extension chunks. An inner `R:N` reference walks the dangling `entries.next` pointer → **heap-use-after-free**.

## Vulnerable Code Path

File: `ext/standard/var_unserializer.re`, function `var_destroy` (lines 230–313):

```
Phase 1 (L242-246):  efree all back-ref extension chunks — entries.next left dangling
Phase 2 (L248-313):  walk dtor chain, fire magic methods, then dtor
```

Three lock-free triggers in Phase 2:

| Trigger | Line | Mechanism |
|---------|------|-----------|
| `zval_ptr_dtor(&retval)` | L284 | `__wakeup` return value dtor → `__destruct` |
| `zval_ptr_dtor(&param)` | L302 | `__unserialize` param copy dtor → `__destruct` |
| `i_zval_ptr_dtor(zv)` | L308 | dtor slot itself dtor → `__destruct` |

Reentry flow:
1. `var_destroy` Phase 1 frees extension chunks (`efree_size`)
2. Phase 2 hits lock-free `i_zval_ptr_dtor` → `__destruct` fires
3. `__destruct` calls `unserialize('R:1500;')`
4. `php_var_unserialize_init` reuses outer `var_hash` (lock=0, level=1)
5. `var_access(1500)` follows dangling `entries.next` → UAF read

## Directory Structure

```
var_destroy_uaf/
├── Dockerfile            # Build ASAN-enabled PHP 8.5.5
├── build.sh              # Build script
├── run_poc.sh            # Run all PoCs
├── poc/
│   ├── poc_dtor_v7.php   # PoC 1: L308 trigger (duplicate key + __destruct)
│   ├── poc_L284.php      # PoC 2: L284 trigger (__wakeup returns destruct-bearing obj)
│   └── poc_leak_v2.php   # PoC 3: Heap spray + controlled pointer deref → SEGV
├── exp/
│   ├── exploit_var_destroy_rce.php   # Full RCE exploit (fake zend_closure → system())
│   └── stage1d_offset_finder.php     # Offset discovery tool for other PHP builds
├── vuln-php/
│   ├── ext/standard/
│   │   ├── var_unserializer.re       # Vulnerable source (re2c)
│   │   └── var.c                     # unserialize() entry point
│   └── Zend/
│       ├── zend_interfaces.c         # Calif's bug site (NOT this vuln)
│       └── zend_objects.c            # __destruct dispatch (L172)
└── docs/
    ├── asan-traces/                  # Full ASAN crash traces
    └── patch_zend_interfaces.py      # Calif's patch (does NOT fix this vuln)
```

## Reproduction

### Build
```bash
./build.sh
```

### Run PoCs
```bash
./run_poc.sh
```

Or individually:
```bash
# PoC 1 — L308 trigger
docker run --rm -v "$PWD:/work" php-uaf-var-destroy \
    /php-src/sapi/cli/php /work/poc/poc_dtor_v7.php 2>&1

# PoC 2 — L284 trigger
docker run --rm -v "$PWD:/work" php-uaf-var-destroy \
    /php-src/sapi/cli/php /work/poc/poc_L284.php 2>&1

# PoC 3 — Heap spray + controlled deref
docker run --rm -e ASAN_OPTIONS='abort_on_error=1:halt_on_error=1:quarantine_size_mb=0:detect_leaks=0' \
    -v "$PWD:/work" php-uaf-var-destroy \
    /php-src/sapi/cli/php /work/poc/poc_leak_v2.php 2>&1
```

### Expected Output

All three PoCs trigger ASAN `heap-use-after-free`. PoC 3 additionally demonstrates controlled pointer dereference (SEGV at `0x4141414141414141`).

## Independence from Calif Blog's Bug

Calif proposes adding `BG(serialize_lock)++/--` around `zend_call_method_with_1_params` in `zend_user_unserialize`. That patch does **not** fix this vulnerability — the three lock-free sites are in `var_destroy`, not `zend_user_unserialize`.

| | Blog exploit | This PoC (poc_dtor_v7) |
|---|---|---|
| Unpatched PHP 8.5.5 | succeeds → RCE | ASAN heap-use-after-free |
| Patched PHP 8.5.5 | **fails** | ASAN heap-use-after-free |

## Proposed Fix

Hold `BG(serialize_lock)` over the *entire* dtor walk:

```diff
 PHPAPI void var_destroy(php_unserialize_data_t *var_hashx)
 {
+    BG(serialize_lock)++;
     ...
     while (var_dtor_hash) {
         for (i = 0; i < var_dtor_hash->used_slots; i++) {
-            BG(serialize_lock)++;   // __wakeup
-            // ...
-            BG(serialize_lock)--;
-            BG(serialize_lock)++;   // __unserialize
-            // ...
-            BG(serialize_lock)--;
             i_zval_ptr_dtor(zv);
         }
         ...
     }
+    BG(serialize_lock)--;
 }
```
