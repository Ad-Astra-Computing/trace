"""Seed plumbing invariants for lora/hf_job.py.

lora/hf_job.py imports torch/trl at module scope, so these tests inspect the
source AST instead of importing it. What they pin down:

1. SEED is bound exactly once, from the environment, with default "42" — so a
   dispatch without SEED env runs the identical code path every prior adapter
   (v1.0–v1.10 and the v1.11 seed-42 control arm) trained under. This is the
   no-op-at-s42 argument for the multi-seed refactor: the only change is how
   the constant is bound, and the default binds it to the historical value.
2. Every seed consumer reads the module constant `SEED` — no literal 42 is
   passed to set_seed()/SFTConfig(seed=...), so an env override reaches every
   RNG consumer or none.
"""

import ast
from pathlib import Path

HF_JOB = Path(__file__).resolve().parents[2] / "lora" / "hf_job.py"


def _module():
    return ast.parse(HF_JOB.read_text())


def test_seed_is_env_driven_with_default_42():
    assigns = [
        node
        for node in ast.walk(_module())
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "SEED" for t in node.targets)
    ]
    assert len(assigns) == 1, "SEED must be bound exactly once"
    src = ast.unparse(assigns[0].value)
    assert src == "int(os.environ.get('SEED', '42'))", src


def test_seed_consumers_read_the_module_constant():
    calls = []
    for node in ast.walk(_module()):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
        if name == "set_seed":
            calls.append(("set_seed", node.args, node.keywords))
        if name == "SFTConfig":
            calls.append(("SFTConfig", node.args, node.keywords))
    names = [c[0] for c in calls]
    assert "set_seed" in names and "SFTConfig" in names, names
    for name, args, kwargs in calls:
        if name == "set_seed":
            (arg,) = args
            assert isinstance(arg, ast.Name) and arg.id == "SEED"
        if name == "SFTConfig":
            seed_kw = [k for k in kwargs if k.arg == "seed"]
            assert seed_kw, "SFTConfig must set seed="
            v = seed_kw[0].value
            assert isinstance(v, ast.Name) and v.id == "SEED"
