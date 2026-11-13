"""Shared pieces for the tunnel builders: prompts, validators, status bar, quiet runner."""
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
IFNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,15}$")


# ---------- prompts ----------

def ask(prompt, default=None, validate=None):
    while True:
        suffix = f" [{default}]" if default is not None else ""
        val = input(f"{prompt}{suffix}: ").strip()
        if not val and default is not None:
            val = str(default)
        if not val:
            print("  A value is required.")
            continue
        if validate is None:
            return val
        try:
            return validate(val)
        except ValueError as e:
            print(f"  {e}")


def menu(title, options):
    """Numbered menu; returns the chosen option's key. options: list of (key, label)."""
    print(title)
    for i, (_, label) in enumerate(options, 1):
        print(f"  {i}) {label}")

    def pick(val):
        if not val.isdigit() or not 1 <= int(val) <= len(options):
            raise ValueError(f"Enter a number from 1 to {len(options)}.")
        return options[int(val) - 1][0]
    return ask("Choice", 1, pick)


def choice(options):
    def check(val):
        val = val.lower()
        if val not in options:
            raise ValueError(f"Choose one of: {', '.join(options)}")
        return val
    return check


def tunnel_name(val):
    if not NAME_RE.match(val):
        raise ValueError("Use letters, digits, '-' or '_' (must start with a letter or digit).")
    return val


def ifname(val):
    if not IFNAME_RE.match(val):
        raise ValueError("Interface names are 1-15 chars of letters, digits, '-' or '_'.")
    return val


def network(val):
    try:
        net = ipaddress.IPv4Network(val, strict=True)
    except ValueError as e:
        raise ValueError(f"Not a valid network (e.g. 172.21.0.0/24): {e}")
    if net.prefixlen > 29:
        raise ValueError("Subnet too small for a server plus clients; use /29 or larger.")
    return net


def address(val):
    try:
        return ipaddress.IPv4Address(val)
    except ValueError:
        raise ValueError(f"Not a valid IPv4 address: {val}")


def port(val):
    n = int(val) if val.isdigit() else 0
    if not 1 <= n <= 65535:
        raise ValueError("Port must be 1-65535.")
    return n


def count(val):
    n = int(val) if val.isdigit() else 0
    if n < 1:
        raise ValueError("Need at least 1 client.")
    return n


# ---------- running tools ----------

class BuildError(Exception):
    def __init__(self, message, output=""):
        super().__init__(message)
        self.output = output


class Progress:
    """One-line spinner + progress bar. Silent when stdout isn't a terminal."""
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    WIDTH = 28

    def __init__(self, total):
        self.total = total
        self.done = 0
        self.label = ""
        self.tty = sys.stdout.isatty()
        self._frame = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def __enter__(self):
        if self.tty:
            sys.stdout.write("\x1b[?25l")  # hide cursor
            self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        if self.tty:
            self._thread.join()
            if exc_type is None:
                self.done, self.label = self.total, "Complete"
            self._draw(final=True, ok=exc_type is None)
            sys.stdout.write("\n\x1b[?25h")
            sys.stdout.flush()
        return False

    def step(self, label):
        """Finish the current step (if any) and start the next one."""
        with self._lock:
            if self.label:
                self.done += 1
            self.label = label
        self._draw()

    def _spin(self):
        while not self._stop.wait(0.08):
            self._frame += 1
            self._draw()

    def _draw(self, final=False, ok=True):
        if not self.tty:
            return
        with self._lock:
            filled = self.WIDTH * self.done // self.total
            bar = "█" * filled + "░" * (self.WIDTH - filled)
            pct = 100 * self.done // self.total
            if final:
                icon = "\x1b[32m✔\x1b[0m" if ok else "\x1b[31m✘\x1b[0m"
            else:
                icon = f"\x1b[36m{self.FRAMES[self._frame % len(self.FRAMES)]}\x1b[0m"
            room = shutil.get_terminal_size().columns - self.WIDTH - 9
            label = self.label[:max(room, 0)]
            sys.stdout.write(f"\r\x1b[K{icon} \x1b[32m{bar}\x1b[0m {pct:3d}%  {label}")
            sys.stdout.flush()


def run(cmd, env=None, cwd=None, input=None):
    """Run quietly; return stdout, or raise BuildError carrying the tool's output."""
    result = subprocess.run(cmd, env=env, cwd=cwd, input=input, capture_output=True, text=True)
    if result.returncode != 0:
        name = Path(cmd[0]).name
        args = " ".join(str(c) for c in cmd[1:])
        raise BuildError(f"{name} {args} failed", result.stdout + result.stderr)
    return result.stdout


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
