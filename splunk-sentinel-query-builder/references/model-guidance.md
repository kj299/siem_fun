# Model Guidance

## Use this file when

- refining this skill for Claude Opus 4.6 or Codex GPT-5.4
- tuning prompts for lower token use
- the model keeps answering with too much tutorial content

## Shared guidance

- Keep the answer front-loaded with the query.
- Use a fixed output shape so the model does not improvise structure.
- Prefer exact field names, tables, and indexes over explanatory prose.
- Do not restate obvious syntax rules unless the user asks.
- If the schema is unknown, stop early and return a discovery query.
- Keep the description explicit about what the skill does, when to use it, and when not to use it.
- Keep critical instructions near the top of `SKILL.md`.
- Put examples and troubleshooting in references instead of bloating `SKILL.md`.

## Claude Opus 4.6

- Works best with explicit sections and a crisp task type.
- Benefits from short instruction lists more than long narrative guidance.
- Avoid overlapping rules in multiple files; Claude tends to honor repeated guidance but wastes tokens doing so.
- Good default sections: `Objective`, `Query`, `Assumptions`, `Tuning`, `Validate`.
- Include concrete examples and troubleshooting paths, but keep them in progressive-disclosure references.
- Watch for undertriggering and overtriggering; refine the description instead of adding broad prose.

## Codex GPT-5.4

- Works best when the skill gives a deterministic workflow and clear stop conditions.
- Prefers references that are narrow and callable on demand instead of one long SKILL file.
- Good at making reasonable assumptions, so tell it when to stop guessing and switch to discovery mode.
- Keep model-facing rules operational: what to read, what to emit, what to avoid.
- Align helper metadata with Codex conventions: explicit invocation prompt, optional `openai.yaml`, and focused scope boundaries.

## Anti-patterns

- long tool-agnostic explanations of SPL or KQL
- repeating the same optimization advice in every section
- broad "best practices" lists that do not change the query
- asking multiple schema questions when one discovery query would unblock the work
