"""Export every IDA annotation for this database into notes.json.

Two ways to run it:

*   From the tool: `python autocrackme.py export` starts IDA headless with this
    script, so nothing has to be done by hand.
*   From the IDA GUI: File > Script file... (or Alt+F7), then pick this file. It
    writes notes.json next to the input binary. IDA is left running.

The output is what the skill scorer reads: line comments, function comments and
the names you assigned. Auto-generated names are ignored.
"""

import json
import os
import time

import ida_auto
import ida_bytes
import ida_funcs
import ida_nalt
import ida_name
import ida_pro
import ida_kernwin

TOOL = "autocrackme-ida-export"
VERSION = 1
BADADDR = getattr(ida_bytes, "BADADDR", 0xFFFFFFFFFFFFFFFF)


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
    """Every function in the database."""
    found = []
    for index in range(ida_funcs.get_func_qty()):
        func = ida_funcs.getn_func(index)
        if func is not None:
            found.append(func)
    return found


def _user_named(ea):
    """True when the name at `ea` was set by the user rather than generated."""
    checker = getattr(ida_bytes, "has_user_name", None)
    if callable(checker):
        try:
            return bool(checker(ida_bytes.get_flags(ea), ea))
        except Exception:
            return False
    flags = ida_bytes.get_flags(ea)
    return not ida_bytes.has_dummy_name(flags, ea)


def collect():
    comments = []
    function_comments = []
    renames = []

    for func in _functions():
        start_ea, end_ea = func.start_ea, func.end_ea
        name = ida_funcs.get_func_name(start_ea) or ""
        for repeatable in (0, 1):
            text = ida_funcs.get_func_cmt(func, repeatable)
            if text:
                function_comments.append(
                    {
                        "ea": hex(start_ea),
                        "name": name,
                        "text": text,
                        "repeatable": bool(repeatable),
                    }
                )

        ea = start_ea
        while ea != BADADDR and ea < end_ea:
            if _user_named(ea):
                user_name = ida_name.get_name(ea)
                if user_name:
                    renames.append({"ea": hex(ea), "name": user_name})
            for repeatable in (0, 1):
                text = ida_bytes.get_cmt(ea, repeatable)
                if text:
                    comments.append(
                        {
                            "ea": hex(ea),
                            "function": name,
                            "text": text,
                            "repeatable": bool(repeatable),
                        }
                    )
            next_ea = ida_bytes.next_head(ea, end_ea)
            ea = next_ea if next_ea != BADADDR else end_ea

    return comments, function_comments, renames


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
