"""
The window. Wiring only -- every decision it makes lives in core.py, which needs no display.

The shape is three numbered steps down the page, because the audience this exists for (see
discussion #167: "more users (in particular the Law Enforcement Operator) aren't practice with
CLI") should never have to work out what to do next. Everything that is not one of those three
steps is folded away under Advanced.
"""

from __future__ import annotations

import logging
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from wa_crypt_tools.gui import core

# Marks the worker's terminal message on the log queue, so the final line can never overtake
# the log lines that explain it.
DONE = object()

POLL_MS = 100
# Long enough that typing a path does not stat it once per keystroke, short enough that the
# info pane feels like it is keeping up.
DESCRIBE_DELAY_MS = 400

BACKUP_TYPES = [("WhatsApp backups", "*.crypt12 *.crypt14 *.crypt15"), ("All files", "*.*")]
KEY_TYPES = [("WhatsApp key files", "encrypted_backup.key key"), ("All files", "*.*")]


class Window(ttk.Frame):
    """The single window: pick a key, pick a backup, press Decrypt."""

    def __init__(self, master: tk.Misc):
        super().__init__(master, padding=12)
        self.grid(sticky="nsew")
        master.columnconfigure(0, weight=1)
        master.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.records: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self._describe_job: str | None = None
        # What suggest_output last proposed. While the output field still holds it, the field
        # is ours to keep in step; the moment the user edits it, it is theirs.
        self._suggested = ""
        self._wrapping: list[ttk.Label] = []
        self._wrap_width: int | None = None
        # The backup whose header the Messages pane is currently showing.
        self._described_path: str | None = None

        self.key_mode = tk.StringVar(value="file")
        self.key_file = tk.StringVar()
        self.key_hex = tk.StringVar()
        self.encrypted = tk.StringVar()
        self.output = tk.StringVar()
        self.overwrite = tk.BooleanVar(value=False)
        self.force = tk.BooleanVar(value=False)
        self.no_decompress = tk.BooleanVar(value=False)
        self.low_memory = tk.BooleanVar(value=False)
        self.try_harder = tk.BooleanVar(value=False)
        self.verbose = tk.BooleanVar(value=False)
        self.advanced_open = tk.BooleanVar(value=False)

        row = 0
        row = self._build_key(row)
        row = self._build_backup(row)
        row = self._build_output(row)
        row = self._build_actions(row)
        row = self._build_advanced(row)
        self._build_messages(row)

        self._wrapping.append(self.status)
        self.bind("<Configure>", self._rewrap)
        self.key_mode.trace_add("write", lambda *_: self._sync_key_mode())
        self.encrypted.trace_add("write", lambda *_: self._schedule_describe())
        self._sync_key_mode()
        self._pump_job = self.after(POLL_MS, self._pump)
        # Otherwise Tk fires the pending pump after the widget's commands are gone and Tcl
        # complains to stderr about an invalid command name.
        self.bind("<Destroy>", self._stop_pump)

    # ---------------------------------------------------------------- layout

    def _build_key(self, row: int) -> int:
        box = ttk.Labelframe(self, text="1.  Your key", padding=8)
        box.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        box.columnconfigure(1, weight=1)

        ttk.Radiobutton(box, text="Key file", value="file",
                        variable=self.key_mode).grid(row=0, column=0, sticky="w")
        self.key_file_entry = ttk.Entry(box, textvariable=self.key_file)
        self.key_file_entry.grid(row=0, column=1, sticky="ew", padx=6)
        self.key_file_button = ttk.Button(box, text="Browse…", command=self._pick_key)
        self.key_file_button.grid(row=0, column=2)

        ttk.Radiobutton(box, text="64-character key", value="hex",
                        variable=self.key_mode).grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.key_hex_entry = ttk.Entry(box, textvariable=self.key_hex)
        self.key_hex_entry.grid(row=1, column=1, columnspan=2, sticky="ew",
                                padx=(6, 0), pady=(6, 0))

        hint = ttk.Label(box, foreground="grey40", justify="left",
                         text="The key file is \"encrypted_backup.key\", or just \"key\" for "
                              "older backups. If you kept the 64-character key itself "
                              "instead, paste it on the second line.")
        hint.grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 0))
        self._wrapping.append(hint)
        return row + 1

    def _build_backup(self, row: int) -> int:
        box = ttk.Labelframe(self, text="2.  Encrypted backup", padding=8)
        box.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        box.columnconfigure(0, weight=1)

        line = ttk.Frame(box)
        line.grid(row=0, column=0, sticky="ew")
        line.columnconfigure(0, weight=1)
        ttk.Entry(line, textvariable=self.encrypted).grid(row=0, column=0, sticky="ew")
        ttk.Button(line, text="Browse…",
                   command=self._pick_backup).grid(row=0, column=1, padx=(6, 0))

        self.info = ttk.Label(box, foreground="grey40", justify="left",
                              text="Choose a file and this will say what it is.")
        self.info.grid(row=1, column=0, sticky="w", pady=(8, 0))
        self._wrapping.append(self.info)
        return row + 1

    def _build_output(self, row: int) -> int:
        box = ttk.Labelframe(self, text="3.  Save the decrypted file as", padding=8)
        box.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        box.columnconfigure(0, weight=1)
        ttk.Entry(box, textvariable=self.output).grid(row=0, column=0, sticky="ew")
        ttk.Button(box, text="Browse…",
                   command=self._pick_output).grid(row=0, column=1, padx=(6, 0))
        return row + 1

    def _build_actions(self, row: int) -> int:
        bar = ttk.Frame(self)
        bar.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        bar.columnconfigure(0, weight=1)

        self.status = ttk.Label(bar, text="", justify="left")
        self.status.grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=120)
        self.progress.grid(row=0, column=1, padx=(0, 8))
        self.progress.grid_remove()
        self.decrypt_button = ttk.Button(bar, text="Decrypt", command=self.start)
        self.decrypt_button.grid(row=0, column=2)
        return row + 1

    def _build_advanced(self, row: int) -> int:
        self.advanced_button = ttk.Button(self, text="▸  Advanced", width=16,
                                          command=self._toggle_advanced)
        self.advanced_button.grid(row=row, column=0, sticky="w")

        self.advanced = ttk.Frame(self, padding=(12, 6, 0, 6))
        self.advanced.grid(row=row + 1, column=0, sticky="ew")
        self.advanced.grid_remove()
        for i, (var, text) in enumerate([
            (self.overwrite, "Overwrite the output file if it already exists"),
            (self.force, "Write the output even if the checks fail (the result is not "
                         "guaranteed to be your data)"),
            (self.try_harder, "Try harder to find the data (slower; for unusual backups)"),
            (self.no_decompress, "Do not decompress the result"),
            (self.low_memory, "Low-memory mode (for very large backups)"),
            (self.verbose, "Show detailed messages"),
        ]):
            ttk.Checkbutton(self.advanced, text=text, variable=var,
                            ).grid(row=i, column=0, sticky="w")
        return row + 2

    def _build_messages(self, row: int) -> None:
        box = ttk.Labelframe(self, text="Messages", padding=6)
        box.grid(row=row, column=0, sticky="nsew")
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)
        self.rowconfigure(row, weight=1)

        self.log = tk.Text(box, height=8, wrap="word", state="disabled",
                           relief="flat", background="white", highlightthickness=0)
        self.log.grid(row=0, column=0, sticky="nsew")
        bar = ttk.Scrollbar(box, orient="vertical", command=self.log.yview)
        bar.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=bar.set)
        self.log.tag_configure("ERROR", foreground="#b00020")
        self.log.tag_configure("WARNING", foreground="#a05000")
        self.log.tag_configure("DEBUG", foreground="grey45")

    # --------------------------------------------------------------- helpers

    def _sync_key_mode(self) -> None:
        by_file = self.key_mode.get() == "file"
        for widget, on in ((self.key_file_entry, by_file), (self.key_file_button, by_file),
                           (self.key_hex_entry, not by_file)):
            widget.state(["!disabled"] if on else ["disabled"])

    def _toggle_advanced(self) -> None:
        opening = not self.advanced_open.get()
        self.advanced_open.set(opening)
        self.advanced_button.configure(text=("▾  Advanced" if opening
                                             else "▸  Advanced"))
        (self.advanced.grid if opening else self.advanced.grid_remove)()

    def _pick_key(self) -> None:
        chosen = filedialog.askopenfilename(title="Choose your key file", filetypes=KEY_TYPES)
        if chosen:
            self.key_file.set(chosen)

    def _pick_backup(self) -> None:
        chosen = filedialog.askopenfilename(title="Choose the encrypted backup",
                                            filetypes=BACKUP_TYPES)
        if chosen:
            self.encrypted.set(chosen)

    def _pick_output(self) -> None:
        chosen = filedialog.asksaveasfilename(title="Save the decrypted file as",
                                              initialfile=Path(self.output.get()).name or None)
        if chosen:
            self.output.set(chosen)
            self._suggested = ""

    def _schedule_describe(self) -> None:
        if self._describe_job is not None:
            self.after_cancel(self._describe_job)
        self._describe_job = self.after(DESCRIBE_DELAY_MS, self._describe)

    def _busy_working(self) -> bool:
        return self.worker is not None and self.worker.is_alive()

    def _describe(self) -> None:
        self._describe_job = None
        path = self.encrypted.get().strip()
        # The output field follows the backup until the user takes it over.
        if self.output.get() in ("", self._suggested):
            self._suggested = core.suggest_output(path)
            self.output.set(self._suggested)
        if not path:
            self._say_info("Choose a file and this will say what it is.", "grey40")
            self._show_detail(path, "")
            return
        if not Path(path).is_file():
            self._say_info("There is no file at that path.", "#b00020")
            self._show_detail(path, "")
            return
        try:
            found = core.describe_backup(path)
        except Exception as e:  # noqa: BLE001 - any failure here is just "cannot describe it"
            self._say_info(core.friendly(e).split("\n")[0], "#b00020")
            self._show_detail(path, "")
            return
        headline = found.headline
        if found.warning:
            headline += f"\n⚠ {found.warning}"
        self._say_info(headline, "#a05000" if found.warning else "grey30")
        # The full header goes where it is available without being in the way.
        self._show_detail(path, found.detail)

    def _say_info(self, text: str, colour: str) -> None:
        self.info.configure(text=text, foreground=colour)

    def _show_detail(self, path: str, text: str) -> None:
        """
        Puts a newly chosen file's header in the Messages pane.

        Only a *new* file's, which is what keeps the pane from being taken back off a run.
        Describing is debounced, so a timer armed by the last keystroke can land during or
        after the decryption it triggered; without this the run's log would be replaced by
        the header again, which is exactly what a screenshot of the finished window showed.
        """
        if path == self._described_path:
            return
        self._described_path = path
        self._replace_log(text)

    def _replace_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        if text:
            self.log.insert("end", text + "\n")
        self.log.configure(state="disabled")

    def _rewrap(self, event: tk.Event) -> None:
        """
        Keeps the prose labels wrapping to the window rather than to a fixed guess.

        The early return is not just a saving: re-wrapping changes a label's requested size,
        which can put another <Configure> on the queue, so reacting to a width that has not
        actually changed is how this turns into a resize loop.
        """
        width = max(event.width - 60, 240)
        if width == self._wrap_width:
            return
        self._wrap_width = width
        for label in self._wrapping:
            label.configure(wraplength=width)

    def _busy(self, busy: bool) -> None:
        self.decrypt_button.state(["disabled"] if busy else ["!disabled"])
        if busy:
            self.progress.grid()
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.grid_remove()

    def _append(self, levelno: int, text: str) -> None:
        tag = logging.getLevelName(levelno)
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n", tag if tag in ("ERROR", "WARNING", "DEBUG") else "")
        self.log.see("end")
        self.log.configure(state="disabled")

    # ------------------------------------------------------------------ work

    def start(self) -> None:
        """Validates the form and, if it holds up, runs the decryption on a worker thread."""
        if self._busy_working():
            return
        key = self.key_file.get() if self.key_mode.get() == "file" else self.key_hex.get()
        found = core.problems(key=key, key_is_file=self.key_mode.get() == "file",
                              encrypted=self.encrypted.get(), output=self.output.get(),
                              overwrite=self.overwrite.get())
        if found:
            messagebox.showwarning("Not ready yet", "\n\n".join(found), parent=self)
            return

        if self._describe_job is not None:
            # It would land mid-run and overwrite the log with the header again.
            self.after_cancel(self._describe_job)
            self._describe_job = None
        self._replace_log("")
        self.status.configure(text="Working…", foreground="grey30")
        self._busy(True)

        self.worker = threading.Thread(target=self._work, daemon=True, kwargs={
            "key": "".join(key.split()) if self.key_mode.get() == "hex" else key,
            "encrypted": self.encrypted.get(), "output": self.output.get(),
            "force": self.force.get(), "overwrite": self.overwrite.get(),
            "no_decompress": self.no_decompress.get(), "low_memory": self.low_memory.get(),
            "try_harder": self.try_harder.get(), "verbose": self.verbose.get()})
        self.worker.start()

    def _work(self, verbose: bool, **kwargs) -> None:
        with core.captured_logs(self.records, verbose=verbose):
            try:
                core.run_decrypt(**kwargs)
            except BaseException as e:  # noqa: BLE001 - it is reported, not swallowed
                self.records.put((DONE, e))
                return
            self.records.put((DONE, None))

    def _pump(self) -> None:
        """Drains the worker's queue into the widgets, from the thread Tk allows."""
        try:
            while True:
                kind, payload = self.records.get_nowait()
                if kind is DONE:
                    self._finished(payload)
                else:
                    self._append(kind, payload)
        except queue.Empty:
            pass
        self._pump_job = self.after(POLL_MS, self._pump)

    def _stop_pump(self, _event: tk.Event) -> None:
        if self._pump_job is not None:
            self.after_cancel(self._pump_job)
            self._pump_job = None

    def _finished(self, error: BaseException | None) -> None:
        self._busy(False)
        if error is None:
            self.status.configure(text=f"Saved to {self.output.get()}",
                                  foreground="#1b7f3b")
            return
        self.status.configure(text="Could not decrypt this backup.", foreground="#b00020")
        # An error needs reading, and the explanation is longer than the status line: a modal
        # is the one place it cannot be missed.
        messagebox.showerror("Could not decrypt", core.friendly(error), parent=self)


def build(master: tk.Misc | None = None) -> Window:
    """Creates the window. Separate from main() so the tests can build one and drive it."""
    root = master if master is not None else tk.Tk()
    root.title("WhatsApp Crypt Tools")
    root.minsize(640, 700)
    # The default X11 theme is a Motif throwback; clam is the closest thing Tk has to a
    # neutral modern look, and it exists everywhere. Windows and macOS keep their native
    # themes, which are already right.
    if ("clam" in root.tk.call("ttk::themes")
            and root.tk.call("tk", "windowingsystem") == "x11"):
        ttk.Style(root).theme_use("clam")
    return Window(root)


def _has_tkinter() -> bool:
    try:
        import tkinter  # noqa: F401
        return True
    except ImportError:  # pragma: no cover - only in a build that lost Tk
        return False


def version() -> str:
    try:
        from importlib.metadata import version as _version
        return _version("wa-crypt-tools")
    # Reporting the version must not be able to stop the program starting, and a frozen
    # build can fail this in more ways than ImportError.
    except Exception:  # noqa: BLE001  # pragma: no cover - only in a build without metadata
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    """Entry point for the `wagui` script and the frozen binaries."""
    argv = sys.argv[1:] if argv is None else argv
    # Parsed before Tk is touched, so a windowed binary can still be smoke-tested in CI.
    if "--version" in argv or "-V" in argv:
        print(f"wagui (wa-crypt-tools {version()})")
        return 0
    if "--selftest" in argv:
        # What CI runs against each frozen binary. --version alone proves too little: the
        # generated protobuf modules are imported inside DatabaseFactory.from_file, so they
        # are the one thing a PyInstaller build can silently leave out, and the failure would
        # otherwise reach a user as a window that dies on the first backup they open.
        from wa_crypt_tools.proto import backup_prefix_pb2
        backup_prefix_pb2.BackupPrefix()
        print(f"wagui selftest ok (wa-crypt-tools {version()}, tkinter available: {_has_tkinter()})"
              )
        return 0
    if "--help" in argv or "-h" in argv:
        print("usage: wagui\n\nOpens the WhatsApp Crypt Tools window.\n"
              "For the command-line tools, see wadecrypt, waencrypt, wainfo, "
              "wacreatekey and waguess.")
        return 0
    window = build()
    window.winfo_toplevel().mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
