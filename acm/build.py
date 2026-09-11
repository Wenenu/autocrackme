"""Compiling and running the generated crackmes with MSVC.

A `build.bat` is written next to each challenge so it can also be rebuilt by
hand. It initialises the Visual Studio environment itself, which avoids the
quoting mess of passing `cl` a long command line through a shell.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import Settings

SOURCE_NAME = "crackme.c"
EXE_NAME = "crackme.exe"
BUILD_SCRIPT = "build.bat"


class BuildError(RuntimeError):
    pass


@dataclass
class BuildResult:
    exe: Path
    log: str


def build_script_text(
    settings: Settings,
    *,
    source: str = SOURCE_NAME,
    exe: str = EXE_NAME,
    obj_dir: str | None = None,
) -> str:
    """The batch file's contents, run from the challenge directory."""
    if not settings.vcvars:
        raise BuildError(
            "No Visual Studio (vcvars64.bat) found. Install the MSVC build tools, "
            "or set \"vcvars_path\" in config.json."
        )
    vcvars = settings.vcvars
    if settings.arch == "x86":
        vcvars = vcvars.with_name("vcvars32.bat")
    optimize = "/O2" if settings.optimize else "/Od"
    windows_source = source.replace("/", "\\")
    obj_flag = ""
    if obj_dir:
        windows_obj_dir = obj_dir.replace("/", "\\") + "\\"
        obj_flag = f" /Fo:{windows_obj_dir}"
    return f"""@echo off
set "VCVARS={vcvars}"
if not exist "%VCVARS%" (
  echo VCVARS_MISSING
  exit /b 1
)
call "%VCVARS%" >nul 2>&1
if errorlevel 1 (
  echo VCVARS_FAILED
  exit /b 1
)
cd /d "%~dp0"
cl /nologo {optimize} /W3 "{windows_source}"{obj_flag} /Fe:{exe}
if errorlevel 1 (
  echo COMPILE_FAILED
  exit /b 2
)
echo BUILD_OK
exit /b 0
"""


def write_build_script(
    directory: Path,
    settings: Settings,
    *,
    source: str = SOURCE_NAME,
    exe: str = EXE_NAME,
    obj_dir: str | None = None,
) -> Path:
    path = Path(directory) / BUILD_SCRIPT
    path.write_text(
        build_script_text(settings, source=source, exe=exe, obj_dir=obj_dir),
        encoding="utf-8",
        newline="\r\n",
    )
    return path


def build(
    directory: Path,
    settings: Settings,
    *,
    source: str = SOURCE_NAME,
    exe: str = EXE_NAME,
    obj_dir: str | None = None,
    timeout: int = 300,
) -> BuildResult:
    """Compile a generated source, returning the exe path."""
    script = write_build_script(directory, settings, source=source, exe=exe, obj_dir=obj_dir)
    try:
        proc = subprocess.run(
            ["cmd", "/c", str(script)],
            cwd=str(directory),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise BuildError(f"compilation timed out after {timeout}s") from exc

    log = ((proc.stdout or "") + (proc.stderr or "")).strip()
    target = Path(directory) / exe
    if not target.exists():
        raise BuildError(f"compilation failed (exit {proc.returncode}):\n{log}")
    return BuildResult(exe=target, log=log)


def run(exe: Path, password: str, *, timeout: int = 20) -> tuple[int, str]:
    """Feed one line to the crackme and return its exit code and output."""
    try:
        proc = subprocess.run(
            [str(exe)],
            input=password + "\n",
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124, "<timed out>"
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def accepts(exe: Path, password: str) -> bool:
    """Run the crackme to see whether it really accepts this input.

    This is what makes scoring objective: the report is checked against the
    binary rather than trusted.
    """
    code, _ = run(exe, password)
    return code == 0
