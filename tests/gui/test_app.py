"""
The window, driven without a mouse.

These need a display, so they skip where there is none -- a headless runner, or a Python built
without _tkinter. Everything that can be tested without one is in test_core.py; what is left
here is the wiring itself: that the widgets come up, that the fields feed core, and that the
worker's result gets back into the pane it belongs in.
"""

from __future__ import annotations

import time

import pytest

from tests.utils.utils import cmp_files

tk = pytest.importorskip("tkinter")

KEY15 = "tests/res/encrypted_backup.key"
PLAIN = "tests/res/msgstore.db"
BACKUP = "tests/res/msgstore.db.crypt15"


@pytest.fixture
def window():
    """A real window, or a skip if this machine cannot show one."""
    from wa_crypt_tools.gui.app import build

    try:
        root = tk.Tk()
    except tk.TclError as e:
        pytest.skip(f"no display available: {e}")
    root.withdraw()
    w = build(root)
    try:
        yield w
    finally:
        root.destroy()


def pump(window, seconds=30):
    """Runs the event loop until the worker is done, the way mainloop would."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        window.update()
        if window.worker is not None and not window.worker.is_alive() and window.records.empty():
            window.update()
            return
        time.sleep(0.02)
    raise AssertionError("the worker did not finish in time")


def log_text(window):
    return window.log.get("1.0", "end").strip()


class TestWindow:
    def test_it_builds(self, window):
        assert window.winfo_toplevel().title() == "WhatsApp Crypt Tools"

    def test_advanced_starts_closed(self, window):
        # grid_info rather than winfo_ismapped: the root is withdrawn, so nothing is mapped.
        assert window.advanced.grid_info() == {}
        window._toggle_advanced()
        assert window.advanced.grid_info() != {}
        assert "▾" in window.advanced_button.cget("text")

    def test_the_key_mode_disables_the_other_field(self, window):
        assert "disabled" in window.key_hex_entry.state()
        window.key_mode.set("hex")
        assert "disabled" not in window.key_hex_entry.state()
        assert "disabled" in window.key_file_entry.state()

    def test_choosing_a_backup_describes_it_and_names_the_output(self, window):
        window.encrypted.set(BACKUP)
        window._describe()
        assert "Crypt15 backup" in window.info.cget("text")
        assert window.output.get() == "tests/res/msgstore.db"
        # The full header lands in the pane, where it is out of the way.
        assert "IV:" in log_text(window)

    def test_a_file_that_is_not_a_backup_says_so_without_a_traceback(self, window):
        window.encrypted.set(PLAIN)
        window._describe()
        text = window.info.cget("text")
        assert "Error" not in text and "Traceback" not in text
        assert text

    def test_decrypting_writes_the_file_and_reports_it(self, window, tmp_path):
        out = tmp_path / "msgstore.db"
        window.key_file.set(KEY15)
        window.encrypted.set(BACKUP)
        window.output.set(str(out))
        window.start()
        pump(window)
        assert cmp_files(str(out), PLAIN)
        assert "Saved to" in window.status.cget("text")
        # The run's log owns the pane once it starts, not the header from step 2.
        assert "IV:" not in log_text(window)
        assert "Raw key loaded" in log_text(window)

    def test_a_repeat_describe_cannot_wipe_the_run_log(self, window, tmp_path):
        # The describe is debounced, so a timer armed by the last keystroke can land after
        # the decryption it triggered. Before this was fixed it replaced the run log with
        # the header again -- which is what a screenshot of the finished window showed.
        out = tmp_path / "msgstore.db"
        window.key_file.set(KEY15)
        window.encrypted.set(BACKUP)
        window.output.set(str(out))
        window._describe()
        assert "IV:" in log_text(window)
        window.start()
        pump(window)
        window._describe()
        assert "Raw key loaded" in log_text(window)

    def test_starting_cancels_a_pending_describe(self, window, tmp_path):
        window.key_file.set(KEY15)
        window.encrypted.set(BACKUP)  # arms the debounce timer
        window.output.set(str(tmp_path / "msgstore.db"))
        assert window._describe_job is not None
        window.start()
        assert window._describe_job is None
        pump(window)

    def test_the_wrong_key_reports_without_writing(self, window, tmp_path, monkeypatch):
        shown = {}
        monkeypatch.setattr(
            "tkinter.messagebox.showerror", lambda title, message, **kw: shown.update(title=title, text=message)
        )
        out = tmp_path / "msgstore.db"
        window.key_mode.set("hex")
        window.key_hex.set("00" * 32)
        window.encrypted.set(BACKUP)
        window.output.set(str(out))
        window.start()
        pump(window)
        assert not out.exists()
        assert "Could not decrypt" in window.status.cget("text")
        assert "not the right key" in shown["text"]

    def test_a_form_with_problems_never_starts_a_worker(self, window, monkeypatch):
        warned = {}
        monkeypatch.setattr("tkinter.messagebox.showwarning", lambda title, message, **kw: warned.update(text=message))
        window.key_file.set("")
        window.encrypted.set("")
        window.output.set("")
        window.start()
        assert window.worker is None
        assert "key file" in warned["text"]

    def test_the_output_field_stops_following_once_edited(self, window):
        window.encrypted.set(BACKUP)
        window._describe()
        window.output.set("somewhere/else.db")
        window.encrypted.set("tests/res/msgstore.db.crypt14")
        window._describe()
        assert window.output.get() == "somewhere/else.db"


class TestEntryPoint:
    def test_version_does_not_need_a_display(self, capsys):
        from wa_crypt_tools.gui.app import main

        assert main(["--version"]) == 0
        assert "wa-crypt-tools" in capsys.readouterr().out

    def test_selftest_loads_the_lazy_protobuf_modules(self, capsys):
        # This is what CI runs against each frozen binary; if it can pass here but fail
        # there, the PyInstaller spec is missing something.
        from wa_crypt_tools.gui.app import main

        assert main(["--selftest"]) == 0
        assert "selftest ok" in capsys.readouterr().out

    def test_help_does_not_need_a_display(self, capsys):
        from wa_crypt_tools.gui.app import main

        assert main(["--help"]) == 0
        assert "wadecrypt" in capsys.readouterr().out
