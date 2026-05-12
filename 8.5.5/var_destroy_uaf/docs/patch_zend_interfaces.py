#!/usr/bin/env python3
"""Apply blog's BG(serialize_lock)++ fix to zend_user_unserialize."""
import sys

P = "/root/php-audit/php-8.5.5/Zend/zend_interfaces.c"
src = open(P).read()

# Strip any include we added in earlier failed attempts.
for inc in (
    '#include "ext/standard/php_var.h"\n',
    '#include "ext/standard/basic_functions.h"\n',
    '#include "ext/standard/php_string.h"\n',
    '#include "php.h"\n',
):
    src = src.replace(inc, "")

# Add a clean include of php.h (which is what var_unserializer.re uses).
old_inc = '#include "zend_interfaces.h"'
new_inc = '#include "zend_interfaces.h"\n#include "php.h"\n#include "ext/standard/basic_functions.h"'
if old_inc in src:
    src = src.replace(old_inc, new_inc, 1)

# Apply BG(serialize_lock)++ around zend_call_method_with_1_params.
old_call = (
    '\tZVAL_STRINGL(&zdata, (char*)buf, buf_len);\n'
    '\tzend_call_method_with_1_params(\n'
    '\t\tZ_OBJ_P(object), Z_OBJCE_P(object), NULL, "unserialize", NULL, &zdata);\n'
    '\tzval_ptr_dtor(&zdata);'
)
new_call = (
    '\tZVAL_STRINGL(&zdata, (char*)buf, buf_len);\n'
    '\tBG(serialize_lock)++;\n'
    '\tzend_call_method_with_1_params(\n'
    '\t\tZ_OBJ_P(object), Z_OBJCE_P(object), NULL, "unserialize", NULL, &zdata);\n'
    '\tBG(serialize_lock)--;\n'
    '\tzval_ptr_dtor(&zdata);'
)
already_patched = (
    'BG(serialize_lock)++;' in src
    and 'zend_call_method_with_1_params' in src
)
if old_call in src:
    src = src.replace(old_call, new_call, 1)
elif not already_patched:
    sys.exit("could not locate zend_call_method_with_1_params block")

open(P, "w").write(src)
print("patched OK")
