"""Talking to the EXTRACTED concrete evaluator.

`run_net --serve` runs a network program and prints what it did.  Using it as
the oracle removes a whole trust assumption from the property tests: the thing
they compare against is the same evaluator the Coq development is about and the
same one the IR's own expect tests exercise, rather than a reimplementation of
the semantics in Python.

The cost is a process boundary, so the process is spawned ONCE and kept alive;
per-run cost is then a write and a read.
"""

import atexit
import os
import subprocess
import tempfile

RUN_NET = os.path.expanduser(
    "~/proj/ir/_build/default/extracted_code/RunNet.exe")

_WIDTH = {1: 8, 2: 16, 4: 32, 8: 64}


class RunnerUnavailable(Exception):
    pass


class IrRunner:
    """A co-process wrapper.  `observe` returns the evaluator's report for one
    run as a list of lines, which is exactly what two runs need to be compared
    on -- emitted packet, then every region's contents and access extent."""

    def __init__(self, exe=RUN_NET):
        if not os.path.exists(exe):
            raise RunnerUnavailable(
                "%s does not exist; build it with\n"
                "  cd ~/proj/ir && dune build --profile release" % exe)
        self.proc = subprocess.Popen(
            [exe, "--serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, bufsize=1)
        self._dir = tempfile.mkdtemp(prefix="irrun-")
        self._path = os.path.join(self._dir, "prog.ir")
        atexit.register(self.close)

    def _command(self, line):
        if self.proc.poll() is not None:
            raise RunnerUnavailable("the runner exited (%d)" % self.proc.returncode)
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        out = []
        while True:
            got = self.proc.stdout.readline()
            if got == "":
                raise RunnerUnavailable("the runner closed its output")
            got = got.rstrip("\n")
            if got == ".":
                return out
            out.append(got)

    def observe(self, ir_text, seeds=()):
        """Run `ir_text` with the given (region, offset, nbytes, value) seeds.

        Returns the evaluator's report.  A rejecting run reports just
        ["reject"], which is the whole observable -- two runs that both reject
        are indistinguishable, exactly as the equivalence checker treats them.
        """
        with open(self._path, "w") as f:
            f.write(ir_text)
        self._command("forget " + self._path)
        spec = "".join(" %d:%d:%d:%d" % (r, off, _WIDTH[n], v)
                       for (r, off, n, v) in seeds)
        return self._command("run " + self._path + spec)

    def close(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.stdin.write("quit\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()


_shared = None


def shared():
    """One runner per pytest process."""
    global _shared
    if _shared is None:
        _shared = IrRunner()
    return _shared


def emitted_u32(report):
    """The 32 bits the deparser emitted, from a report's first line."""
    if not report or report[0].startswith("reject"):
        return None
    head = report[0]
    body = head[head.index("[") + 1: head.index("]")]
    val = 0
    for b in body.split(","):
        val = (val << 8) | (int(b.strip()) & 0xff)
    return val
