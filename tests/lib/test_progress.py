from wa_crypt_tools.wadecrypt import format_progress


def test_format_progress_uses_a_fixed_width_bar():
    assert format_progress(0, 100, width=4) == "Decrypting [....]   0%"
    assert format_progress(50, 100, width=4) == "Decrypting [==..]  50%"
    assert format_progress(150, 100, width=4) == "Decrypting [====] 100%"


def test_format_progress_handles_an_unknown_total():
    assert format_progress(0, 0, width=4) == "Decrypting [....]"
