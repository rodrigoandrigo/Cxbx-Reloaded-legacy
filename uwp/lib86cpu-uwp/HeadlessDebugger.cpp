#include "lib86cpu_priv.hpp"
#include "dbg/debugger.hpp"
#include "dbg/main_wnd.hpp"

void read_dbg_opt(cpu_t*) {}
void write_dbg_opt(cpu_t*) {}
void dbg_setup_sw_breakpoints(cpu_t*) {}
void dbg_apply_sw_breakpoints(cpu_t*) {}
void dbg_copy_registers(cpu_t*) {}
std::optional<uint8_t> dbg_insert_sw_breakpoint(cpu_t*, addr_t) { return std::nullopt; }
void dbg_remove_sw_breakpoints(cpu_t*) {}
void dbg_remove_sw_breakpoints(cpu_t*, addr_t) {}
std::vector<std::pair<addr_t, std::string>> dbg_disas_code_block(cpu_t*, addr_t, unsigned) { return {}; }
void dbg_exp_handler(cpu_ctx_t*) {}
void dbg_ram_read(cpu_t*, uint8_t*) {}
void dbg_ram_write(uint8_t*, size_t, uint8_t) {}
void dbg_update_watchpoint(cpu_t*, uint32_t, addr_t, uint32_t, uint32_t, bool) {}
void dbg_apply_watchpoints(cpu_t*) {}
void dbg_main_wnd(cpu_t*, std::promise<bool>& promise) { promise.set_value(true); }
void dbg_should_close() {}

