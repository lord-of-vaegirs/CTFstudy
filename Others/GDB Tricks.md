## GDB Tricks

**不定期不定量更新，每天积累一点点**

1. Use `contextprev` and `contextnext` to display a previous context output again without scrolling
2. Pwndbg mirrors some of WinDbg commands like eq, ew, ed, eb, es, dq, dw, dd, db, ds for writing and reading memory
3. Use the procinfo command for better process introspection (than the GDB's info proc command)
4. GDB's follow-fork-mode parameter can be used to set whether to trace parent or child after fork() calls. Pwndbg sets it to child by default
5. If you want Pwndbg to clear screen on each command (but still save previous output in history) use `set context-clear-screen on`
6. Use `hi` to see if a an address belongs to a glibc heap chunk
7. `heap-config` shows heap related configuration
8. Calling functions like `call (void)puts("hello world")` will run all other target threads for the time the function runs. Use `set scheduler-locking on` to lock the execution to current thread when calling functions
9. Use GDB's `pi` command to run an interactive Python console where you can use Pwndbg APIs like `pwndbg.aglib.memory.read(addr, len)`, `pwndbg.aglib.memory.write(addr, data)`, `pwndbg.aglib.vmmap.get()` and so on!

