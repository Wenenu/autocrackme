"""Export every annotation the solver made, into notes.json.

Two ways to run it:

*   From the tool: `python autocrackme.py export` starts IDA headless with this
    script, so nothing has to be done by hand.
*   From the IDA GUI: File > Script file... (or Alt+F7), then pick this file. It
    writes notes.json next to the input binary. IDA is left running.

The output is what the skill scorer reads, so it has to contain *only* what the
solver wrote. IDA decorates a database heavily on its own, and all of it comes
back through the same `get_cmt`/`get_name` calls as a real annotation:

*   argument and variable names derived from type information (`is_tilcmt`),
*   canned instruction comments such as "Trap to Debugger", which are exactly
    what `get_predef_insn_cmt` returns for that instruction,
*   switch and jump-table annotations, on addresses IDA's switch info covers,
*   library signature text, stored as a *repeatable* function comment,
*   FLIRT-recognised library functions and import-table names.

Without filtering these out, a database nobody has touched exports over a
thousand "comments" and hundreds of "names", and every score is meaningless.
"""

import json
import os
import re
import time

import ida_auto
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt
import ida_pro
import ida_segment
import idautils
import ida_ua

TOOL = "autocrackme-ida-export"
VERSION = 3
BADADDR = getattr(ida_bytes, "BADADDR", 0xFFFFFFFFFFFFFFFF)

FUNC_LIB = getattr(ida_funcs, "FUNC_LIB", 0x4)
FUNC_THUNK = getattr(ida_funcs, "FUNC_THUNK", 0x80)

# Import-table segments: named by IDA, and never written by the solver.
IMPORT_SEGMENT_PREFIXES = (".idata", "extern", "imp")

# The dispatch instruction and the table label of a switch are annotated by IDA
# but are not covered by get_switch_parent, and no flag marks them. These are
# IDA's own formats; a solver has no reason to type one verbatim.
IDA_SWITCH_COMMENT = re.compile(
    r"^(switch \d+ cases|switch jump|jump table for switch statement"
    r"|jumptable [0-9A-Fa-f]+ (case \d+|default case))$"
)

# Names IDA derives from a PE's own metadata (RTTI, load config, the exception
# directory, guard and jump tables) or from MSVC's decorated symbols. This tool
# only ever builds MSVC x64/x86 binaries, so these families cover it. Detecting
# a solver's identifier reliably is not possible otherwise: IDA reports these as
# "user" names too.
IDA_SYMBOL_PATTERNS = (
    re.compile(r"^\?\?"),          # RTTI and vftable (??_R, ??_7)
    re.compile(r"^\?"),            # any MSVC-decorated name (?filt$, ?fin$, ...)
    re.compile(r"^__guard_"),
    re.compile(r"^__castguard_"),
    re.compile(r"^_guard_"),
    re.compile(r"^jpt_"),
    re.compile(r"^__security_cookie$"),
    re.compile(r"^_load_config_used$"),
    re.compile(r"^__volatile_metadata$"),
    re.compile(r"^ExceptionDir$"),
    re.compile(r"^__T[IA]"),
    re.compile(r"^__CT"),
    re.compile(r"^__imp_"),
)


def _ida_version():
    for getter in ("get_kernel_version", "get_ida_version"):
        fn = getattr(ida_kernwin, getter, None)
        if callable(fn):
            try:
                return str(fn())
            except Exception:
                pass
    return ""


def _input_path():
    for getter in ("get_input_file_path", "retrieve_input_file_path"):
        fn = getattr(ida_nalt, getter, None)
        if callable(fn):
            try:
                value = fn()
                if value:
                    return str(value)
            except Exception:
                pass
    return ""


def _functions():
    found = []
    for index in range(ida_funcs.get_func_qty()):
        func = ida_funcs.getn_func(index)
        if func is not None:
            found.append(func)
    return found


def _til_comment(ea):
    """True for a comment IDA derived from type information."""
    checker = getattr(ida_nalt, "is_tilcmt", None)
    if not callable(checker):
        return False
    try:
        return bool(checker(ea))
    except Exception:
        return False


def _predef_comment(ea):
    """The canned comment IDA generates for this instruction, if any."""
    decoder = getattr(ida_ua, "decode_insn", None)
    getter = getattr(ida_bytes, "get_predef_insn_cmt", None)
    if not callable(decoder) or not callable(getter):
        return None
    try:
        insn = ida_ua.insn_t()
        if not decoder(insn, ea):
            return None
        return getter(insn)
    except Exception:
        return None


def _in_switch(ea):
    """True when the address belongs to a switch table (IDA annotates those)."""
    getter = getattr(ida_nalt, "get_switch_parent", None)
    if callable(getter):
        try:
            if getter(ea) != BADADDR:
                return True
        except Exception:
            pass
    try:
        si = ida_nalt.switch_info_t()
        if ida_nalt.get_switch_info(ea, si):
            return True
    except Exception:
        pass
    return False


def _is_generated_comment(ea, text):
    """True when IDA wrote this comment rather than the solver."""
    if _til_comment(ea):
        return True
    predef = _predef_comment(ea)
    if predef is not None and text == predef:
        return True
    if _in_switch(ea):
        return True
    return bool(IDA_SWITCH_COMMENT.match(text))


def _is_user_named(ea, name):
    """True when the name at `ea` looks solver-assigned.

    IDs the solver chose cannot be told apart from names IDA applied for
    statically linked runtime code by any flag; `has_user_name` only means "not
    a dummy name" (`sub_1234`). So everything IDA can vouch for is excluded:
    library functions, thunks, the import table, and the PE/CRT symbol families
    IDA derives from the binary's own metadata.

    Note the arity: `has_user_name` takes the flags word only. Passing an
    address as well used to raise, and the bare `except` turned that into a
    silent "no renames anywhere".
    """
    if any(pattern.match(name) for pattern in IDA_SYMBOL_PATTERNS):
        return False

    func = ida_funcs.get_func(ea)
    if func is not None:
        fflags = getattr(func, "flags", 0)
        if fflags & (FUNC_LIB | FUNC_THUNK):
            return False
    if _in_import_segment(ea):
        return False

    flags = ida_bytes.get_flags(ea)
    checker = getattr(ida_bytes, "has_user_name", None)
    if callable(checker):
        try:
            return bool(checker(flags))
        except Exception:
            pass
    dummy = getattr(ida_bytes, "has_dummy_name", None)
    if callable(dummy):
        try:
            return not bool(dummy(flags))
        except Exception:
            pass
    return False


def _in_import_segment(ea):
    try:
        seg = ida_segment.getseg(ea)
        if seg is None:
            return False
        name = (ida_segment.get_segm_name(seg) or "").lower()
    except Exception:
        return False
    return name.startswith(IMPORT_SEGMENT_PREFIXES)


def _collect_comments():
    """Line and repeatable comments inside functions, minus IDA's own.

    Scoped to function bodies on purpose. Walking every head in the database
    pulls in a large amount of comment-like material IDA attached to data, and
    a crackme is solved by annotating code.
    """
    comments = []
    for func in _functions():
        name = ida_funcs.get_func_name(func.start_ea) or ""
        ea = func.start_ea
        while ea != BADADDR and ea < func.end_ea:
            for repeatable in (0, 1):
                text = ida_bytes.get_cmt(ea, repeatable)
                if text and not _is_generated_comment(ea, text):
                    comments.append(
                        {
                            "ea": hex(ea),
                            "function": name,
                            "text": text,
                            "repeatable": bool(repeatable),
                        }
                    )
            next_ea = ida_bytes.next_head(ea, func.end_ea)
            ea = next_ea if next_ea != BADADDR else func.end_ea
    return comments


def _collect_function_comments():
    """Function comments, non-repeatable only.

    IDA stores library signature text ("Microsoft VisualC ... runtime") in the
    repeatable one, so collecting both counted every CRT routine as annotated.
    """
    found = []
    for func in _functions():
        text = ida_funcs.get_func_cmt(func, 0)
        if not text:
            continue
        found.append(
            {
                "ea": hex(func.start_ea),
                "name": ida_funcs.get_func_name(func.start_ea) or "",
                "text": text,
                "repeatable": False,
            }
        )
    return found


def _collect_renames():
    """Names the solver assigned, anywhere in the database."""
    renames = []
    for ea, name in idautils.Names():
        if name and _is_user_named(ea, name):
            renames.append({"ea": hex(ea), "name": name})
    return renames


def collect():
    return _collect_comments(), _collect_function_comments(), _collect_renames()


def output_path(input_file):
    override = os.environ.get("ACM_NOTES_OUT")
    if override:
        return override
    directory = os.path.dirname(input_file) or "."
    return os.path.join(directory, "notes.json")


def main():
    ida_auto.auto_wait()  # make sure analysis has finished before reading it

    input_file = _input_path()
    comments, function_comments, renames = collect()
    payload = {
        "tool": TOOL,
        "version": VERSION,
        "input_file": input_file,
        "ida_version": _ida_version(),
        "exported_at": time.time(),
        "counts": {
            "comments": len(comments),
            "function_comments": len(function_comments),
            "renames": len(renames),
        },
        "comments": comments,
        "function_comments": function_comments,
        "renames": renames,
    }

    path = output_path(input_file)
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        ida_kernwin.msg(
            "[autocrackme] exported %d comments, %d function comments and %d names to %s\n"
            % (len(comments), len(function_comments), len(renames), path)
        )
    except Exception as exc:  # pragma: no cover - depends on the IDA runtime
        ida_kernwin.msg("[autocrackme] failed to write %s: %s\n" % (path, exc))

    # Only quit when driven headless, otherwise the user's IDA would close.
    if os.environ.get("ACM_HEADLESS") == "1":
        ida_pro.qexit(0)


main()
