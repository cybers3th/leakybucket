import io
import re
import shutil
import subprocess
from importlib.resources import files
from types import SimpleNamespace

import pytest

from firewall.observe.cli import main
from firewall.observe.manual import install_manual, manual_text, roff_page, show_manual


def test_manual_command_does_not_require_service_configuration(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('LB_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setenv('LB_CONFIG_DIR', str(tmp_path / 'config'))
    main(['man', '--plain'])
    output = capsys.readouterr().out
    assert output.startswith('NAME\n')
    for heading in ('INSPECTION MODES', 'CONNECTION OPTIONS', 'POLICY', 'TROUBLESHOOTING', 'EXIT STATUS'):
        assert heading in output
    for command in ('start', 'stop', 'status', 'doctor', 'chat', 'traces', 'trace', 'watch', 'policy validate'):
        assert 'leakybucket ' + command in output
    assert '--rules-only' in output and '{"trace":null}' in output
    assert not (tmp_path / 'state').exists()
    assert not (tmp_path / 'config').exists()


def test_native_page_matches_the_plain_text_source():
    native = files('firewall.observe').joinpath('man/leakybucket.1').read_text(encoding='utf-8')
    assert native == roff_page(manual_text())


def test_install_user_man_page_without_touching_service_state(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path))
    destination = install_manual()
    assert destination == tmp_path / 'man/man1/leakybucket.1'
    assert destination.read_text() == roff_page(manual_text())
    assert destination.stat().st_mode & 0o777 == 0o644
    assert install_manual() == destination
    assert not list(destination.parent.glob('tmp*'))


def test_install_refuses_to_overwrite_an_unmanaged_manual(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path))
    destination = tmp_path / 'man/man1/leakybucket.1'
    destination.parent.mkdir(parents=True)
    destination.write_text('Existing unrelated documentation\n')
    with pytest.raises(ValueError, match='unmanaged'):
        install_manual()
    assert destination.read_text() == 'Existing unrelated documentation\n'


def test_missing_native_viewer_falls_back_to_plain_text(monkeypatch, capsys):
    monkeypatch.setattr('firewall.observe.manual.shutil.which', lambda command: None)
    show_manual()
    assert capsys.readouterr().out == manual_text()


def test_interactive_manual_uses_the_native_viewer_without_a_shell(monkeypatch):
    stream = io.StringIO()
    stream.isatty = lambda: True
    monkeypatch.setattr('firewall.observe.manual.sys.stdout', stream)
    monkeypatch.setattr('firewall.observe.manual.shutil.which', lambda command: '/usr/bin/man')
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        assert args[:2] == ['/usr/bin/man', '-l']
        assert args[2].endswith('leakybucket.1')
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr('firewall.observe.manual.subprocess.run', run)
    show_manual()
    assert len(calls) == 1
    assert calls[0][1] == {'check': False}
    assert stream.getvalue() == ''


def test_native_page_renders_without_roff_errors():
    groff = shutil.which('groff')
    if not groff:
        pytest.skip('groff is not installed')
    result = subprocess.run([groff, '-Tutf8', '-man'], input=roff_page(manual_text()),
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert not result.stderr
    rendered = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)
    rendered = re.sub(r'.\x08', '', rendered)
    assert 'LEAKYBUCKET(1)' in rendered
    assert '127.0.0.1:8080' in rendered
