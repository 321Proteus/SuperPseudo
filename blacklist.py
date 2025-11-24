import ida_kernwin
import ida_funcs
import ida_hexrays
import ida_bytes
import idc
import json
import os

BLACKLIST_PATH = "sp_blacklist.json"

CITEM_OP_NAMES = {
    ida_hexrays.cot_empty: "cot_empty",

    ida_hexrays.cot_comma: "cot_comma   (x, y)",

    ida_hexrays.cot_asg: "cot_asg     (x = y)",
    ida_hexrays.cot_asgbor: "cot_asgbor  (x |= y)",
    ida_hexrays.cot_asgxor: "cot_asgxor  (x ^= y)",
    ida_hexrays.cot_asgband: "cot_asgband (x &= y)",
    ida_hexrays.cot_asgadd: "cot_asgadd  (x += y)",
    ida_hexrays.cot_asgsub: "cot_asgsub  (x -= y)",
    ida_hexrays.cot_asgmul: "cot_asgmul  (x *= y)",
    ida_hexrays.cot_asgsshr: "cot_asgsshr (x >>= y signed)",
    ida_hexrays.cot_asgushr: "cot_asgushr (x >>= y unsigned)",
    ida_hexrays.cot_asgshl: "cot_asgshl  (x <<= y)",
    ida_hexrays.cot_asgsdiv: "cot_asgsdiv (x /= y signed)",
    ida_hexrays.cot_asgudiv: "cot_asgudiv (x /= y unsigned)",
    ida_hexrays.cot_asgsmod: "cot_asgsmod (x %= y signed)",
    ida_hexrays.cot_asgumod: "cot_asgumod (x %= y unsigned)",

    ida_hexrays.cot_tern: "cot_tern  (x ? y : z)",

    ida_hexrays.cot_lor:  "cot_lor   (x || y)",
    ida_hexrays.cot_land: "cot_land  (x && y)",
    ida_hexrays.cot_bor:  "cot_bor   (x | y)",
    ida_hexrays.cot_xor:  "cot_xor   (x ^ y)",
    ida_hexrays.cot_band: "cot_band  (x & y)",

    ida_hexrays.cot_eq: "cot_eq    (x == y int/fpu)",
    ida_hexrays.cot_ne: "cot_ne    (x != y int/fpu)",
    ida_hexrays.cot_sge: "cot_sge   (x >= y signed/fpu)",
    ida_hexrays.cot_uge: "cot_uge   (x >= y unsigned)",
    ida_hexrays.cot_sle: "cot_sle   (x <= y signed/fpu)",
    ida_hexrays.cot_ule: "cot_ule   (x <= y unsigned)",
    ida_hexrays.cot_sgt: "cot_sgt   (x > y signed/fpu)",
    ida_hexrays.cot_ugt: "cot_ugt   (x > y unsigned)",
    ida_hexrays.cot_slt: "cot_slt   (x < y signed/fpu)",
    ida_hexrays.cot_ult: "cot_ult   (x < y unsigned)",

    ida_hexrays.cot_sshr: "cot_sshr  (x >> y signed)",
    ida_hexrays.cot_ushr: "cot_ushr  (x >> y unsigned)",
    ida_hexrays.cot_shl:  "cot_shl   (x << y)",

    ida_hexrays.cot_add: "cot_add   (x + y)",
    ida_hexrays.cot_sub: "cot_sub   (x - y)",
    ida_hexrays.cot_mul: "cot_mul   (x * y)",

    ida_hexrays.cot_sdiv: "cot_sdiv  (x / y signed)",
    ida_hexrays.cot_udiv: "cot_udiv  (x / y unsigned)",
    ida_hexrays.cot_smod: "cot_smod  (x % y signed)",
    ida_hexrays.cot_umod: "cot_umod  (x % y unsigned)",

    ida_hexrays.cot_fadd: "cot_fadd  (x + y fp)",
    ida_hexrays.cot_fsub: "cot_fsub  (x - y fp)",
    ida_hexrays.cot_fmul: "cot_fmul  (x * y fp)",
    ida_hexrays.cot_fdiv: "cot_fdiv  (x / y fp)",

    ida_hexrays.cot_fneg: "cot_fneg  (-x fp)",
    ida_hexrays.cot_neg:  "cot_neg   (-x)",

    ida_hexrays.cot_cast: "cot_cast  ((type)x)",

    ida_hexrays.cot_lnot: "cot_lnot  (!x)",
    ida_hexrays.cot_bnot: "cot_bnot  (~x)",

    ida_hexrays.cot_ptr:   "cot_ptr   (*x, size in ptrsize)",
    ida_hexrays.cot_ref:   "cot_ref   (&x)",
    ida_hexrays.cot_postinc: "cot_postinc (x++)",
    ida_hexrays.cot_postdec: "cot_postdec (x--)",
    ida_hexrays.cot_preinc:  "cot_preinc  (++x)",
    ida_hexrays.cot_predec:  "cot_predec  (--x)",

    ida_hexrays.cot_call: "cot_call   (x(...))",
    ida_hexrays.cot_idx:  "cot_idx    (x[y])",

    ida_hexrays.cot_memref: "cot_memref (x.m)",
    ida_hexrays.cot_memptr: "cot_memptr (x->m, size in ptrsize)",

    ida_hexrays.cot_num:  "cot_num   (n)",
    ida_hexrays.cot_fnum: "cot_fnum  (fpc)",
    ida_hexrays.cot_str:  "cot_str   (string literal)",
    ida_hexrays.cot_obj:  "cot_obj   (obj_ea)",
    ida_hexrays.cot_var:  "cot_var   (v)",

    ida_hexrays.cot_insn: "cot_insn  (instruction expr, internal)",

    ida_hexrays.cot_sizeof: "cot_sizeof (sizeof(x))",

    ida_hexrays.cot_helper: "cot_helper (helper name)",
    ida_hexrays.cot_type:   "cot_type   (arbitrary type)",

    ida_hexrays.cot_last: "cot_last  (end of expr ops)",


    # =============== INSTRUCTIONS ===============
    ida_hexrays.cit_empty: "cit_empty",

    ida_hexrays.cit_block:    "cit_block    ({ ... })",
    ida_hexrays.cit_expr:     "cit_expr     (expr;)",
    ida_hexrays.cit_if:       "cit_if       (if)",
    ida_hexrays.cit_for:      "cit_for      (for)",
    ida_hexrays.cit_while:    "cit_while    (while)",
    ida_hexrays.cit_do:       "cit_do       (do)",
    ida_hexrays.cit_switch:   "cit_switch   (switch)",
    ida_hexrays.cit_break:    "cit_break    (break)",
    ida_hexrays.cit_continue: "cit_continue (continue)",
    ida_hexrays.cit_return:   "cit_return   (return)",
    ida_hexrays.cit_goto:     "cit_goto     (goto)",
    ida_hexrays.cit_asm:      "cit_asm      (asm)",
    ida_hexrays.cit_try:      "cit_try      (try)",
    ida_hexrays.cit_throw:    "cit_throw    (throw)",
}

def op_to_name(op):
    return CITEM_OP_NAMES.get(op, f"unknown_op({op})")

def get_blacklist():
    if os.path.exists(BLACKLIST_PATH):
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
            try: 
                json
                return json.load(f)
            except json.JSONDecodeError:
                with open(BLACKLIST_PATH, "w", encoding="utf-8") as fw:
                    json.dump([], fw, indent=4, ensure_ascii=False)
                return []
    else:
        with open(BLACKLIST_PATH, "w", encoding="utf-8") as f:
            json.dump([], f, indent=4, ensure_ascii=False)
        return []

def blacklist_contains(func):
    blacklist = get_blacklist()
    return func in blacklist

def update_blacklist(func):
    blacklist = get_blacklist()
    if func in blacklist:
        blacklist.remove(func)
    else:
        blacklist.append(func)
    
    with open(BLACKLIST_PATH, "w", encoding="utf-8") as f:
        json.dump(blacklist, f, indent=4, ensure_ascii=False)

def get_call():
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays is not available")
        return

    vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
    if not vu or not vu.cfunc:
        print("Not in a pseudocode view")
        return
    
    # not a citem
    if not vu.item.is_citem():
        print("This is not a ctree element")
        return

    ni = ida_hexrays.citem_to_specific_type(vu.item.it)

    if isinstance(ni, ida_hexrays.cexpr_t):
        ea = ni.obj_ea

        # cot_call only marks the opening bracket character, otherwise it is cot_obj
        if ni.op == ida_hexrays.cot_call:
            callee = ida_hexrays.citem_to_specific_type(ni.x)
            if callee.op == ida_hexrays.cot_obj:
                return idc.get_func_name(callee.obj_ea)

        # check if the cot_obj is a function itself
        elif ni.op == ida_hexrays.cot_obj and ida_funcs.get_func(ea) is not None:
            return idc.get_func_name(ea)

        else:
            return
    else:
        # sometimes cinsn_t is selected instead of cexpr_t
        return

class ToggleActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        call = get_call()
        if call is not None:
            update_blacklist(call)
            print(get_blacklist())


    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS