"""PrismEX source file.

@QK
"""

from prismex.pluginsystem import discover_plugins, run_plugins, PluginContext


def test_builtin_plugins_discovered():
    plugs = discover_plugins(plugin_dirs=None, include_builtins=True)
    assert isinstance(plugs, dict)
    assert "example_metadata" in plugs


def test_plugin_run_writes_output():
    plugs = discover_plugins(plugin_dirs=None, include_builtins=True)
    ctx = PluginContext(analyzer=None, path="/tmp/fake.exe", pe=None, report={"analysis": {}}, options={})
    res = run_plugins(plugins={"example_metadata": plugs["example_metadata"]}, enabled=None, ctx=ctx)
    assert res and res[0]["status"] == "ok"
    assert "plugins" in ctx.report["analysis"]
