import lldb
import commands
import os
import shlex

def rb_vm_insn_addr2insn2(target, result, addr, size):
    translation_table = target.FindFirstGlobalVariable('insns_address_table')
    for insn in range(0, size):
        machine_insn = translation_table.GetChildAtIndex(insn).unsigned
        if machine_insn == addr:
            return insn
    return False

def display_unknown(target, result, iseqs, offset, op_type):
    print >> result, "neat"
    print >> result, op_type
    print >> result, op_type.unsigned

def display_id(target, result, iseqs, offset, op_type):
    addr = iseqs.GetChildAtIndex(offset, lldb.eNoDynamicValues, 1).unsigned
    print >> result, "ID: " + str(addr)

def display_callcache(target, result, iseqs, offset, op_type):
    rb_call_info = target.FindFirstType("struct rb_call_cache").GetPointerType()
    addr = iseqs.GetChildAtIndex(offset, lldb.eNoDynamicValues, 1).Cast(rb_call_info)
    print >> result, addr.Dereference()

def display_callinfo(target, result, iseqs, offset, op_type):
    rb_call_info = target.FindFirstType("struct rb_call_info").GetPointerType()
    addr = iseqs.GetChildAtIndex(offset, lldb.eNoDynamicValues, 1).Cast(rb_call_info)
    print >> result, addr.Dereference()

def display_lindex(target, result, iseqs, offset, op_type):
    addr = iseqs.GetChildAtIndex(offset, lldb.eNoDynamicValues, 1).unsigned
    print >> result, "lindex: %d" % addr

def display_ic(target, result, iseqs, offset, op_type):
    rb_call_info = target.FindFirstType("struct iseq_inline_cache_entry").GetPointerType()
    addr = iseqs.GetChildAtIndex(offset, lldb.eNoDynamicValues, 1).Cast(rb_call_info)
    print >> result, addr.Dereference()

def display_iseq(target, result, iseqs, offset, op_type):
    rb_call_info = target.FindFirstType("struct rb_iseq_struct").GetPointerType()
    addr = iseqs.GetChildAtIndex(offset, lldb.eNoDynamicValues, 1).Cast(rb_call_info)
    print >> result, addr.Dereference()

def display_num(target, result, iseqs, offset, op_type):
    addr = iseqs.GetChildAtIndex(offset, lldb.eNoDynamicValues, 1).unsigned
    print >> result, "rb_num_t: %d" % addr

def display_offset(target, result, iseqs, offset, op_type):
    addr = iseqs.GetChildAtIndex(offset, lldb.eNoDynamicValues, 1).unsigned
    print >> result, "OFFSET: %lu" % addr

def display_value(target, result, iseqs, offset, op_type):
    tRBasic = target.FindFirstType("struct RBasic").GetPointerType()
    addr = iseqs.GetChildAtIndex(offset, lldb.eNoDynamicValues, 1).Cast(tRBasic)
    print >> result, addr.Dereference()

def display_op(op):
    return {
            73: display_id,
            69: display_callcache,
            67: display_callinfo,
            76: display_lindex,
            75: display_ic,
            83: display_iseq,
            78: display_num,
            79: display_offset,
            86: display_value,
    }.get(op, display_unknown)


def iseq_extract_values(target, result, iseqs, n):
    name_info = target.FindFirstGlobalVariable('rb_vm_insn_name_base')
    offset    = target.FindFirstGlobalVariable('rb_vm_insn_op_offset')
    op_info   = target.FindFirstGlobalVariable('rb_vm_insn_op_info')
    addr      = iseqs.GetChildAtIndex(n, lldb.eNoDynamicValues, 1).unsigned
    size      = target.EvaluateExpression('ruby_vminsn_type::VM_INSTRUCTION_SIZE').unsigned
    orig_insn = rb_vm_insn_addr2insn2(target, result, addr, size)

    consumed = 1

    name = name_info.GetChildAtIndex(orig_insn, lldb.eNoDynamicValues, 1)
    print >> result, "Instruction: %s" % name

    op_offset = offset.GetChildAtIndex(orig_insn, lldb.eNoDynamicValues, 1).unsigned
    op_type = op_info.GetChildAtIndex(op_offset, lldb.eNoDynamicValues, 1)
    while op_type.unsigned > 0:
        display_op(op_type.unsigned)(target, result, iseqs, n + consumed, op_type)
        op_offset += 1
        consumed += 1
        op_type = op_info.GetChildAtIndex(op_offset, lldb.eNoDynamicValues, 1)

    return consumed

def disasm(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    if frame.IsValid():
        val = frame.EvaluateExpression(command)
    else:
        val = target.EvaluateExpression(command)
    error = val.GetError()
    if error.Fail():
        print >> result, error
        return

    tRbISeq = target.FindFirstType("struct rb_iseq_struct").GetPointerType()
    val = val.Cast(tRbISeq)
    iseq_size = val.GetValueForExpressionPath("->body->iseq_size").GetValueAsUnsigned()
    iseqs = val.GetValueForExpressionPath("->body->iseq_encoded")
    idx = 0
    while idx < iseq_size:
        idx += iseq_extract_values(target, result, iseqs, idx)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("command script add -f lldb_disasm.disasm disasm")
    print "lldb Ruby disasm installed."
