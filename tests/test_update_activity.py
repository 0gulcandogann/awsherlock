"""Updater keeps installer logs and has no animation."""
import subprocess
from unittest.mock import Mock
import pytest
from typer.testing import CliRunner
from awsherlock.cli import REPOSITORY_URL, app


def test_update_pipx_launcher_replaces_stale_package_source(monkeypatch):
    monkeypatch.setattr('awsherlock.cli.importlib.util.find_spec', lambda name: None)
    monkeypatch.setattr(
        'awsherlock.cli.shutil.which',
        lambda name: r'C:\Windows\py.EXE' if name == 'py' else None,
    )
    run = Mock()
    monkeypatch.setattr('awsherlock.cli.subprocess.run', run)

    result = CliRunner().invoke(app, ['--update'])

    assert result.exit_code == 0, result.output
    run.assert_called_once_with(
        [r'C:\Windows\py.EXE', '-m', 'pipx', 'install', '--force', REPOSITORY_URL],
        check=True,
    )

@pytest.mark.parametrize('failures,code', [(0,0),(1,0),(2,1),('interrupt',130)])
def test_update_logs_and_fallback(monkeypatch,failures,code):
    monkeypatch.setattr('awsherlock.cli.importlib.util.find_spec',lambda name: object())
    monkeypatch.setattr('awsherlock.cli.shutil.which',lambda name: 'pipx' if name=='pipx' else None)
    outcomes = [KeyboardInterrupt()] if failures=='interrupt' else [subprocess.CalledProcessError(1,'installer')]*failures+[None]
    run=Mock(side_effect=outcomes)
    monkeypatch.setattr('awsherlock.cli.subprocess.run',run)
    result=CliRunner().invoke(app,['--update'])
    assert result.exit_code==code,result.output
    assert all(call.kwargs=={'check':True} for call in run.call_args_list)
    assert '--force-reinstall' in run.call_args_list[0].args[0]
    assert ('updated successfully' in result.output)==(code==0)
    if failures==1:
        assert run.call_args_list[1].args[0] == ['pipx', 'install', '--force', REPOSITORY_URL]

@pytest.mark.parametrize('args',[[],['--help']])
def test_boxed_root_examples(monkeypatch,args):
    updater=Mock(side_effect=AssertionError('Help must not update'))
    monkeypatch.setattr('awsherlock.cli.update_installation',updater)
    result=CliRunner().invoke(app,args,env={'COLUMNS':'120'})
    assert result.exit_code==0,result.output
    assert 'Quick start' in result.output and 'awsherlock --update' in result.output
    assert 'spinner' not in result.output
    section=result.output.split('Quick start',1)[1]
    assert '?' in section and 'awsherlock scan facts.json' in section
    updater.assert_not_called()

def test_options_title_is_lighter_without_changing_border():
    from typer import rich_utils
    from awsherlock.terminal import PURPLE
    assert rich_utils.OPTIONS_PANEL_TITLE=='[bold #c7a4e8]Options[/]'
    assert rich_utils.COMMANDS_PANEL_TITLE=='[bold #8be9fd]Commands[/]'
    assert rich_utils.STYLE_OPTIONS_PANEL_BORDER==PURPLE
    assert rich_utils.STYLE_COMMANDS_PANEL_BORDER==PURPLE
