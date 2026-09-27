"""
The window, driven without a mouse.

These need a display, so they skip where there is none -- a headless runner, or a Python built
without _tkinter. Everything that can be tested without one is in test_core.py; what is left
here is the wiring itself: that the widgets come up, that the fields feed core, and that the
worker's result gets back into the pane it belongs in.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

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
        assert "Crypt15 backup" in window.info_label.cget("text")
        assert window.output.get() == "tests/res/msgstore.db"
        # The full header lands in the pane, where it is out of the way.
        assert "IV:" in log_text(window)

    def test_a_file_that_is_not_a_backup_says_so_without_a_traceback(self, window):
        window.encrypted.set(PLAIN)
        window._describe()
        text = window.info_label.cget("text")
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


class TestBrowseButtons:
    """
    The three Browse buttons, driven without a file dialog.

    They are one line each and all three have the same shape -- put what the dialog returned
    into the field, and leave the field alone if the user cancelled -- except that choosing
    an output is also what stops the output field following the backup.
    """

    def test_choosing_a_key_fills_the_field(self, window, monkeypatch):
        monkeypatch.setattr("tkinter.filedialog.askopenfilename", lambda **kw: KEY15)
        window._pick_key()
        assert window.key_file.get() == KEY15

    def test_choosing_a_backup_fills_the_field(self, window, monkeypatch):
        monkeypatch.setattr("tkinter.filedialog.askopenfilename", lambda **kw: BACKUP)
        window._pick_backup()
        assert window.encrypted.get() == BACKUP

    def test_choosing_an_output_takes_the_field_over(self, window, monkeypatch):
        window.encrypted.set(BACKUP)
        window._describe()
        assert window._suggested == window.output.get()
        monkeypatch.setattr("tkinter.filedialog.asksaveasfilename", lambda **kw: "somewhere/chosen.db")
        window._pick_output()
        assert window.output.get() == "somewhere/chosen.db"
        # Cleared, so the next backup does not overwrite what the user just picked.
        assert window._suggested == ""

    @pytest.mark.parametrize("picker", ["_pick_key", "_pick_backup", "_pick_output"])
    def test_cancelling_leaves_everything_alone(self, window, monkeypatch, picker):
        # An empty string is what the dialog returns when it is dismissed.
        monkeypatch.setattr("tkinter.filedialog.askopenfilename", lambda **kw: "")
        monkeypatch.setattr("tkinter.filedialog.asksaveasfilename", lambda **kw: "")
        window.key_file.set(KEY15)
        window.encrypted.set(BACKUP)
        window.output.set("mine.db")
        getattr(window, picker)()
        assert (window.key_file.get(), window.encrypted.get(), window.output.get()) == (KEY15, BACKUP, "mine.db")


class TestDescribing:
    def test_an_empty_field_asks_for_a_file(self, window):
        window.encrypted.set("")
        window._describe()
        assert "Choose a file" in window.info_label.cget("text")

    def test_a_path_with_nothing_at_it_says_so(self, window):
        window.encrypted.set("tests/res/there-is-no-such-file")
        window._describe()
        assert window.info_label.cget("text") == "There is no file at that path."

    def test_a_suspect_header_is_described_with_its_warning(self, window, monkeypatch):
        # The factory hands back what it managed to parse along with the reason it does not
        # trust it; both belong next to the field, the warning under the headline.
        from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
        from wa_crypt_tools.lib.errors import IntegrityError

        with open(BACKUP, "rb") as f:
            salvaged = DatabaseFactory.from_file(f)

        def suspect(_stream):
            raise IntegrityError("IV is not 16 bytes long", data=salvaged)

        monkeypatch.setattr(DatabaseFactory, "from_file", staticmethod(suspect))
        window.encrypted.set(BACKUP)
        window._describe()
        text = window.info_label.cget("text")
        assert "Crypt15 backup" in text
        assert "⚠ IV is not 16 bytes long" in text

    def test_a_second_keystroke_replaces_the_pending_describe(self, window):
        # Each keystroke arms a timer; the one before it has to be cancelled or a path being
        # typed would be described once per character.
        window.encrypted.set("tests/res/msgstore")
        first = window._describe_job
        window.encrypted.set(BACKUP)
        assert window._describe_job is not None
        assert window._describe_job != first


class TestWindowChrome:
    def test_the_labels_rewrap_when_the_window_is_resized(self, window):
        window._rewrap(SimpleNamespace(width=800))
        assert window._wrap_width == 740
        assert all(int(label.cget("wraplength")) == 740 for label in window._wrapping)

    def test_a_configure_event_that_changes_nothing_is_ignored(self, window):
        # Re-wrapping changes a label's requested size, which can put another <Configure> on
        # the queue: reacting to a width that has not changed is how that becomes a loop.
        window._rewrap(SimpleNamespace(width=800))
        window._wrapping[0].configure(wraplength=1)
        window._rewrap(SimpleNamespace(width=800))
        assert int(window._wrapping[0].cget("wraplength")) == 1

    def test_a_second_start_while_one_is_running_is_ignored(self, window, tmp_path):
        # A worker that says it is alive rather than a real one: whether a decryption has
        # finished by the time the second click arrives is exactly the timing this must not
        # depend on.
        class StillRunning:
            def is_alive(self):
                return True

        window.key_file.set(KEY15)
        window.encrypted.set(BACKUP)
        window.output.set(str(tmp_path / "msgstore.db"))
        window.worker = StillRunning()
        window.start()
        assert isinstance(window.worker, StillRunning)
        assert not (tmp_path / "msgstore.db").exists()


class TestEntryPoint:
    def test_the_package_re_exports_main_lazily(self):
        # pyproject's entry point is wa_crypt_tools.gui:main, and gui/__init__.py resolves
        # that name through a PEP 562 __getattr__ rather than importing app.py eagerly --
        # which is what keeps tests/gui/test_core.py collectable without _tkinter.
        import wa_crypt_tools.gui as package
        from wa_crypt_tools.gui.app import main

        assert package.main is main

    def test_the_window_is_built_and_handed_to_the_event_loop(self, monkeypatch):
        # main() with no arguments does exactly two things, and mainloop() never returns in
        # a real run, so this is the only place they can be checked.
        from wa_crypt_tools.gui import app

        looped = []

        class FakeWindow:
            def winfo_toplevel(self):
                return self

            def mainloop(self):
                looped.append(True)

        monkeypatch.setattr(app, "build", FakeWindow)
        assert app.main([]) == 0
        assert looped == [True]

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
