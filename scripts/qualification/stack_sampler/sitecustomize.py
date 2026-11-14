"""Opt-in stack sampler for the performance lane's API process (diagnostics only).

The lane puts this directory on ``PYTHONPATH`` and sets
``QUALIFICATION_STACK_FILE`` only when ``QUALIFICATION_STACK_SAMPLES=1``.
Every 50 ms one daemon thread records, for each thread with agent_bom frames,
the newest four of them: ``epoch<TAB>thread<TAB>file:function:line > ...``.
It reads frame metadata only, never locals or arguments, so no evidence or
secret reaches the file.
"""

import os

_TARGET = os.environ.get("QUALIFICATION_STACK_FILE")

if _TARGET:
    import sys
    import threading
    import time
    import traceback

    def _sample() -> None:
        me = threading.get_ident()
        with open(f"{_TARGET}.{os.getpid()}.tsv", "a", buffering=1, encoding="utf-8") as out:
            while True:
                time.sleep(0.05)
                stamp = time.time()
                names = {thread.ident: thread.name for thread in threading.enumerate()}
                for ident, frame in sys._current_frames().items():
                    if ident == me:
                        continue
                    frames = [item for item in traceback.extract_stack(frame) if "agent_bom" in item.filename]
                    if not frames:
                        continue
                    name = names.get(ident, str(ident))
                    chain = " > ".join(f"{os.path.basename(item.filename)[:-3]}:{item.name}:{item.lineno}" for item in frames[-4:])
                    out.write(f"{stamp:.2f}\t{name}\t{chain}\n")

    threading.Thread(target=_sample, name="qualification-stack-sampler", daemon=True).start()
