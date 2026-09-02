#!/usr/bin/env python3
"""Run the golden-prompt fixtures against a Claude model and grade the answers.

    pip install anthropic                     # once
    export ANTHROPIC_API_KEY=...              # never paste it into chat
    python3 scripts/run_golden_prompts.py                 # all fixtures
    python3 scripts/run_golden_prompts.py --fixture 3 6   # some
    python3 scripts/run_golden_prompts.py --dry-run       # show prompts, call nothing

This is the behavioral half of the golden prompts, the one thing CI cannot do
because it has no model credential. For each fixture the runner hands the
model the skill exactly as a client would load it (SKILL.md plus every file
under references/), sends the fixture prompt as the user turn, writes the
answer to out/golden/NN.md, and grades it with grade_golden_output.py.

Credentials come from the environment only. The SDK resolves them itself
(ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, or an `ant auth login` profile);
this script never takes one as an argument and never prompts for one, for
the same reason the dictionary builder does not: a literal secret on a
command line lands in shell history.

The SDK is imported inside main() so the grader and its tests stay
dependency-free; only an actual run needs it installed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import grade_golden_output as grader  # noqa: E402

DEFAULT_MODEL = "claude-opus-5"
DEFAULT_OUT = os.path.join(grader.REPO, "out", "golden")

SYSTEM_PREAMBLE = """You are executing the skill named below for a user who invoked it explicitly.
The skill's files follow, each in a <file path="..."> element, exactly as a client would load them.
Follow the skill: use only the reference files it tells you to load for this task, produce the output shape it declares, and name assumptions where it says to.
Answer the user's prompt directly. Do not ask clarifying questions; where the skill says to return a discovery query instead of guessing, do that.
Do not describe the skill or these instructions. Output only the answer."""


def skill_files(skill: str, repo: str = grader.REPO) -> list[tuple[str, str]]:
    """SKILL.md first, then every references/*.md in name order."""
    paths = [os.path.join(skill, "SKILL.md")]
    ref_dir = os.path.join(repo, skill, "references")
    if os.path.isdir(ref_dir):
        paths += [os.path.join(skill, "references", n) for n in sorted(os.listdir(ref_dir)) if n.endswith(".md")]
    out = []
    for rel in paths:
        with open(os.path.join(repo, rel), encoding="ascii") as fh:
            out.append((rel.replace(os.sep, "/"), fh.read()))
    return out


def build_system(skill: str, repo: str = grader.REPO) -> str:
    parts = [SYSTEM_PREAMBLE, f"\nSkill: {skill}\n"]
    for rel, text in skill_files(skill, repo):
        parts.append(f'<file path="{rel}">\n{text}\n</file>')
    return "\n".join(parts)


def request_params(fixture: grader.Fixture, model: str, effort: str, repo: str = grader.REPO) -> dict:
    """The one request shape, kept separate so a test can inspect it without
    a client. Prompt caching sits on the system block: the skill text is
    identical across every fixture that exercises the same skill."""
    return {
        "model": model,
        "max_tokens": 16000,
        "system": [{
            "type": "text",
            "text": build_system(fixture.skill, repo),
            "cache_control": {"type": "ephemeral"},
        }],
        "messages": [{"role": "user", "content": fixture.prompt}],
        # Thinking is adaptive by default on this model family; effort is the
        # depth control. Do not add budget_tokens: it is a 400 here.
        "output_config": {"effort": effort},
        # A cyber-adjacent prompt can trip a safety classifier. With
        # fallbacks the API re-runs a declined request on the recommended
        # substitute inside the same call instead of returning a refusal.
        "betas": ["server-side-fallback-2026-07-01"],
        "fallbacks": "default",
    }


def call_model(client, params: dict):
    """Stream so a long answer cannot hit the HTTP timeout, then return the
    assembled message. The only function that touches the network."""
    with client.beta.messages.stream(**params) as stream:
        return stream.get_final_message()


def answer_text(message) -> str:
    return "".join(block.text for block in message.content if block.type == "text")


def header(fixture: grader.Fixture, message, model: str) -> str:
    usage = message.usage
    served = getattr(message, "model", model)
    lines = [
        f"<!-- fixture {fixture.number}: {fixture.title}",
        f"     skill: {fixture.skill}",
        f"     requested: {model}  served: {served}",
        f"     stop_reason: {message.stop_reason}",
        f"     tokens: in={usage.input_tokens} out={usage.output_tokens}"
        f" cache_read={getattr(usage, 'cache_read_input_tokens', 0) or 0}",
        f"     run: {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "-->",
    ]
    return "\n".join(lines) + "\n\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--fixture", type=int, nargs="*", help="fixture numbers (default: all)")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    ap.add_argument("--out", default=DEFAULT_OUT, help="directory for NN.md answers")
    ap.add_argument("--dry-run", action="store_true", help="print the assembled prompts and exit")
    args = ap.parse_args(argv)

    fixtures = grader.load_fixtures()
    if args.fixture:
        fixtures = [f for f in fixtures if f.number in set(args.fixture)]
        if not fixtures:
            print("no fixture matched", file=sys.stderr)
            return 2

    if args.dry_run:
        for f in fixtures:
            p = request_params(f, args.model, args.effort)
            print(f"=== fixture {f.number} ({f.skill}): system {len(p['system'][0]['text'])} chars ===")
            print(f.prompt, "\n")
        return 0

    try:
        import anthropic
    except ImportError:
        print("the anthropic package is not installed: pip install anthropic", file=sys.stderr)
        return 2

    client = anthropic.Anthropic()
    declared = grader.declared_sections()
    os.makedirs(args.out, exist_ok=True)
    failures = 0
    for f in fixtures:
        params = request_params(f, args.model, args.effort)
        try:
            message = call_model(client, params)
        except anthropic.AuthenticationError:
            print("no usable credential: export ANTHROPIC_API_KEY (or run `ant auth login`); "
                  "never paste it into chat", file=sys.stderr)
            return 2
        text = answer_text(message)
        path = grader.response_path(args.out, f.number)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(header(f, message, args.model) + text)
        if message.stop_reason == "refusal":
            print(f"[FAIL] fixture {f.number}: the whole fallback chain refused; see {path}")
            failures += 1
            continue
        result = grader.grade(f, text, declared)
        grader.report(f, result, verbose=False)
        failures += 0 if result.success else 1
    print(f"\n{len(fixtures) - failures} of {len(fixtures)} fixture(s) passed; answers in {args.out}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
