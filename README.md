# avstack.py
[avstack.pl](https://dlbeer.co.nz/oss/avstack.html) ported to Python 3 because I can write python better than I can write perl.

# Additional features
## Scriptable
You can import avstack and use `calculate_stack` to incorporate stack checking
in other scripts.

## Function whitelist
My .o files contain many functions which are never called and are thus optimised
out of the final binary. The stack calculation can optionally accept a function
whitelist generated from the final binary's symbol table to filter results.

## Dummy functions (indirect calls)
If you want to manually add edges that are not automatically detected due to
the use of function pointers, make a second dummy function containing calls to
the real functions. Prefix its name with `__stack_check_dummy__` and it will
be picked up.

For example, if you have a function:
```c
int test(void) {
    return some_function_pointer();
}
```

... and you know that `some_function_pointer` always points to `real_func`,
create the dummy function:
```c
void __stack_check_dummy__test(void) {
    real_func();
}
```

This function will be optimised out by the compiler as it is never called,
but will exist in the intermediate .o file and thus be picked up by avstack.
