"""
Sentinel YARA Rule Generator — NiceGUI Interface
Requires: pip install nicegui yara-x requests
Run with: python sentinel_ui.py
"""

import asyncio
import datetime
import os
import shutil
import tempfile
from pathlib import Path
import sys
from nicegui import app, run, ui


# sentinel_ui.py lives at Sentinel/frontend/sentinel_ui.py
# .parent = Sentinel/frontend/, .parent.parent = Sentinel/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_ROOT = PROJECT_ROOT / "backend"
sys.path.insert(0, str(PROJECT_ROOT))   # allows: from backend.X import ...
sys.path.insert(0, str(BACKEND_ROOT))   # allows bare: import Verifier (used inside LanguageProcessor)

try:
    from backend.Verifier import yarac
    from backend.Deployer import scan as deployer_scan
    import backend.LanguageProcessor as LP
    BACKEND_AVAILABLE = True
except Exception as _import_err:
    print(f"[Sentinel] Backend unavailable — running in demo mode.\n  Reason: {_import_err}")
    BACKEND_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RULES_DIR = Path.cwd() / "rules"
RULES_DIR.mkdir(exist_ok=True)

STAGES = [
    ("generate",  "Generating YARA Rule"),
    ("verify",    "Verifying Syntax"),
    ("review",    "Reviewing Rule"),
    ("deploy",    "Deploying"),
]

STAGE_INDEX = {k: i for i, (k, _) in enumerate(STAGES)}

# ---------------------------------------------------------------------------
# Colour / style tokens  (no gradients)
# ---------------------------------------------------------------------------
BG          = "#0d1117"
SURFACE     = "#161b22"
SURFACE2    = "#1c2230"
BORDER      = "#30363d"
ACCENT      = "#58a6ff"
ACCENT2     = "#1f6feb"
SUCCESS     = "#3fb950"
WARNING     = "#d29922"
DANGER      = "#f85149"
TEXT_MAIN   = "#e6edf3"
TEXT_MUTED  = "#8b949e"
MONO        = "'JetBrains Mono', 'Fira Mono', monospace"

GLOBAL_CSS = f"""
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600&display=swap');

body, .nicegui-content {{
    background: {BG} !important;
    color: {TEXT_MAIN};
    font-family: 'Inter', sans-serif;
}}

/* ── scrollbar ── */
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: {BG}; }}
::-webkit-scrollbar-thumb {{ background: {BORDER}; border-radius: 3px; }}

/* ── cards ── */
.s-card {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 20px;
}}

/* ── section headings ── */
.s-label {{
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: {TEXT_MUTED};
    margin-bottom: 6px;
}}

/* ── log pane ── */
.log-pane {{
    background: {BG};
    border: 1px solid {BORDER};
    border-radius: 6px;
    font-family: {MONO};
    font-size: 12px;
    color: {TEXT_MAIN};
    padding: 12px 14px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
    min-height: 240px;
    max-height: 480px;
    line-height: 1.6;
}}

/* ── rule preview ── */
.rule-preview {{
    background: {BG};
    border: 1px solid {BORDER};
    border-radius: 6px;
    font-family: {MONO};
    font-size: 12px;
    color: #79c0ff;
    padding: 12px 14px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
    min-height: 160px;
    max-height: 340px;
    line-height: 1.6;
}}

/* ── stage pill ── */
.stage-pill {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
}}
.pill-idle    {{ background: {SURFACE2}; color: {TEXT_MUTED}; border: 1px solid {BORDER}; }}
.pill-active  {{ background: #1f3a5f;    color: {ACCENT};     border: 1px solid {ACCENT2}; }}
.pill-done    {{ background: #122a1a;    color: {SUCCESS};    border: 1px solid #2ea043; }}
.pill-error   {{ background: #3b1219;    color: {DANGER};     border: 1px solid #8d2c35; }}

/* ── primary button ── */
.q-btn.btn-primary {{
    background: {ACCENT2} !important;
    color: #fff !important;
    font-weight: 600;
    border-radius: 6px;
    text-transform: none;
    letter-spacing: 0;
    font-size: 13px;
}}
.q-btn.btn-primary:hover {{ background: #388bfd !important; }}

/* ── danger button ── */
.q-btn.btn-danger {{
    background: #8d2c35 !important;
    color: #fff !important;
    border-radius: 6px;
    text-transform: none;
    font-size: 13px;
}}

/* ── success button ── */
.q-btn.btn-success {{
    background: #1a4d27 !important;
    color: {SUCCESS} !important;
    border-radius: 6px;
    text-transform: none;
    font-size: 13px;
}}

/* ── text input overrides ── */
.q-field__control {{
    background: {BG} !important;
    border: 1px solid {BORDER} !important;
    border-radius: 6px !important;
    color: {TEXT_MAIN} !important;
}}
.q-field--focused .q-field__control {{ border-color: {ACCENT} !important; }}
.q-field__native {{ color: {TEXT_MAIN} !important; }}
.q-field__label {{ color: {TEXT_MUTED} !important; }}

/* ── upload area ── */
.q-uploader {{
    background: {SURFACE} !important;
    border: 1px dashed {BORDER} !important;
    border-radius: 8px !important;
    color: {TEXT_MUTED} !important;
}}
.q-uploader__header {{ background: {SURFACE2} !important; }}

/* ── divider ── */
.s-divider {{ border-top: 1px solid {BORDER}; margin: 16px 0; }}

/* ── scan results table ── */
.scan-result {{ padding: 6px 0; border-bottom: 1px solid {BORDER}; font-family: {MONO}; font-size: 12px; }}
.scan-hit  {{ color: {DANGER}; }}
.scan-clean {{ color: {SUCCESS}; }}
"""


# ---------------------------------------------------------------------------
# Helper: LLM stream wrapper (runs in thread, pushes lines to a queue)
# ---------------------------------------------------------------------------

def _llm_generate(prompt: str, model_type: str, queue: asyncio.Queue, yarac: bool = False):
    """Blocking call using OpenAI SDK via OpenRouter; each token chunk is put onto the async queue."""
    from openai import OpenAI

    MODEL_URL = LP.MODEL_URL if BACKEND_AVAILABLE else "https://openrouter.ai/api/v1"
    API_KEY   = LP.API_KEY   if BACKEND_AVAILABLE else "demo"

    if BACKEND_AVAILABLE:
        sys_prompt = LP.LLM1_PROMPT if model_type == "LLM1" else LP.LLM2_PROMPT
    else:
        sys_prompt = "You are a YARA rule generation assistant."

    print(f"[DEBUG] _llm_generate called | type={model_type} yarac={yarac}", flush=True)
    print(f"[DEBUG] MODEL_URL={MODEL_URL}", flush=True)
    print(f"[DEBUG] API_KEY={'<set>' if API_KEY and API_KEY != 'demo' else '<missing or demo>'}", flush=True)
    print(f"[DEBUG] Prompt (first 120 chars): {prompt[:120]!r}", flush=True)

    full = ""
    try:
        client = OpenAI(base_url=MODEL_URL, api_key=API_KEY)
        print(f"[DEBUG] OpenAI client created, sending request...", flush=True)
        response = client.chat.completions.create(
            model="openai/gpt-oss-120b:free",
            messages=[
                {"role": "system",  "content": sys_prompt},
                {"role": "user",    "content": prompt},
            ],
            stream=True,
        )
        print(f"[DEBUG] Stream opened, reading chunks...", flush=True)
        chunk_count = 0
        for chunk in response:
            content = chunk.choices[0].delta.content
            if content is not None:
                full += content
                chunk_count += 1
                queue.put_nowait(("token", content))
                if chunk_count == 1:
                    print(f"[DEBUG] First token received.", flush=True)
        print(f"[DEBUG] Stream complete. Total chunks: {chunk_count}, total chars: {len(full)}", flush=True)
    except Exception as e:
        print(f"[DEBUG] Exception in _llm_generate: {type(e).__name__}: {e}", flush=True)
        queue.put_nowait(("error", str(e)))
    queue.put_nowait(("done", full))
    return full


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

@ui.page("/")
def sentinel_page():

    # ── inject CSS (must be inside the page function when using @ui.page) ──
    ui.add_head_html(
        f"<style>{GLOBAL_CSS}"
        "@keyframes spin {{ from {{ transform:rotate(0deg); }} to {{ transform:rotate(360deg); }} }}"
        "</style>"
    )

    # ── state ──────────────────────────────────────────────────────────────
    state = {
        "running":       False,
        "current_stage": None,   # one of the STAGES keys
        "stage_status":  {k: "idle" for k, _ in STAGES},  # idle|active|done|error
        "final_rule":    "",
        "uploads":       [],     # list of (filename, bytes)
    }

    # ── top bar ────────────────────────────────────────────────────────────
    with ui.element("div").style(
        f"background:{SURFACE}; border-bottom:1px solid {BORDER}; "
        "padding:14px 28px; display:flex; align-items:center; gap:14px;"
    ):
        ui.html('<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>')
        ui.label("SENTINEL").style(
            f"font-family:{MONO}; font-size:18px; font-weight:700; "
            f"color:{ACCENT}; letter-spacing:0.15em;"
        )
        ui.label("YARA Rule Generation Pipeline").style(
            f"font-size:12px; color:{TEXT_MUTED}; margin-top:2px;"
        )
        ui.space()
        backend_dot = "●" if BACKEND_AVAILABLE else "○"
        backend_col = SUCCESS if BACKEND_AVAILABLE else WARNING
        ui.label(f"{backend_dot} Backend {'connected' if BACKEND_AVAILABLE else 'not detected (demo mode)'}").style(
            f"font-size:11px; color:{backend_col}; font-family:{MONO};"
        )

    # ── main layout ────────────────────────────────────────────────────────
    with ui.element("div").style("padding:24px; max-width:1200px; margin:0 auto;"):

        # ── Pipeline stage tracker ─────────────────────────────────────────
        with ui.element("div").classes("s-card").style("margin-bottom:18px;"):
            ui.label("PIPELINE STATUS").classes("s-label")
            with ui.row().style("gap:10px; flex-wrap:wrap; margin-top:8px;"):
                pill_refs: dict[str, ui.html] = {}
                icons = {"generate": "⚙", "verify": "✔", "review": "🔍", "deploy": "🚀"}
                for key, label in STAGES:
                    pill = ui.html(
                        f'<span class="stage-pill pill-idle">'
                        f'{icons[key]} {label}</span>'
                    )
                    pill_refs[key] = pill

            progress_bar = ui.linear_progress(value=0).props("instant-feedback").style(
                f"margin-top:12px; height:4px; border-radius:2px; "
                f"color:{ACCENT}; background:{SURFACE2};"
            )

        # ── Two-column body ────────────────────────────────────────────────
        with ui.row().style("gap:18px; align-items:flex-start;"):

            # ── LEFT: inputs ───────────────────────────────────────────────
            with ui.column().style("flex:1; min-width:300px; gap:16px;"):

                # Description input
                with ui.element("div").classes("s-card"):
                    ui.label("RULE DESCRIPTION").classes("s-label")
                    prompt_input = ui.textarea(
                        placeholder="Describe what you want to detect, e.g. 'Identify Emotet loader DLLs that use XOR obfuscation and drop a PE payload…'"
                    ).style(
                        f"width:100%; min-height:100px; font-family:{MONO}; font-size:12px;"
                    ).props("outlined autogrow")

                # File upload
                with ui.element("div").classes("s-card"):
                    ui.label("UPLOAD SAMPLE FILES").classes("s-label")
                    ui.label("Optional: upload malware samples to scan after rule generation.").style(
                        f"font-size:11px; color:{TEXT_MUTED}; margin-bottom:8px;"
                    )

                    uploaded_label = ui.label("No files uploaded.").style(
                        f"font-size:11px; color:{TEXT_MUTED}; font-family:{MONO};"
                    )

                    def handle_upload(e):
                        content = e.content.read()
                        state["uploads"].append((e.name, content))
                        uploaded_label.set_text(
                            "\n".join(f"📄 {n} ({len(b):,} bytes)" for n, b in state["uploads"])
                        )
                        ui.notify(f"Uploaded: {e.name}", color="positive")

                    uploader = ui.upload(
                        multiple=True,
                        on_upload=handle_upload,
                        label="Drop files here or click to browse",
                        auto_upload=True,
                    ).style("width:100%;")

                    def clear_uploads():
                        state["uploads"].clear()
                        uploaded_label.set_text("No files uploaded.")
                        uploader.reset()

                    ui.button("Clear uploads", on_click=clear_uploads).style(
                        f"margin-top:6px; font-size:11px; color:{TEXT_MUTED}; "
                        "background:transparent; border:none; cursor:pointer; padding:0;"
                    ).props("flat dense")

                # Action buttons
                with ui.row().style("gap:10px;"):
                    run_btn  = ui.button("▶  Generate & Deploy", on_click=lambda: start_pipeline()).classes("btn-primary").style("flex:1;")
                    stop_btn = ui.button("■  Stop", on_click=lambda: stop_pipeline()).classes("btn-danger").style("width:90px;")
                    stop_btn.visible = False

            # ── RIGHT: outputs ─────────────────────────────────────────────
            with ui.column().style("flex:1.4; min-width:320px; gap:16px;"):

                # Live log
                with ui.element("div").classes("s-card"):
                    with ui.row().style("justify-content:space-between; align-items:center; margin-bottom:8px;"):
                        ui.label("LIVE LOG").classes("s-label").style("margin:0;")
                        ui.button("Clear", on_click=lambda: log_pane.set_content("")).props("flat dense").style(
                            f"font-size:11px; color:{TEXT_MUTED};"
                        )
                    log_pane = ui.html("").classes("log-pane")

                # Generated rule
                with ui.element("div").classes("s-card"):
                    ui.label("GENERATED RULE").classes("s-label")
                    rule_pane = ui.html('<span style="color:#555;">Awaiting generation…</span>').classes("rule-preview")

                # Deploy panel (hidden until review is done)
                deploy_panel = ui.element("div").classes("s-card").style("display:none;")
                with deploy_panel:
                    ui.label("DEPLOY RULE").classes("s-label")
                    ui.label("Review the rule above carefully before deploying.").style(
                        f"font-size:12px; color:{TEXT_MUTED}; margin-bottom:10px;"
                    )
                    with ui.row().style("gap:10px;"):
                        deploy_btn = ui.button("🚀  Deploy Rule", on_click=lambda: do_deploy()).classes("btn-success")
                        reject_btn = ui.button("✕  Reject", on_click=lambda: do_reject()).classes("btn-danger")

                # Scan results (shown if files uploaded)
                scan_panel = ui.element("div").classes("s-card").style("display:none;")
                with scan_panel:
                    ui.label("SCAN RESULTS").classes("s-label")
                    scan_results_container = ui.column().style("gap:4px; margin-top:8px;")

    # ── helpers ────────────────────────────────────────────────────────────

    log_buffer = [""]   # mutable container

    def log(msg: str, color: str = TEXT_MAIN, prefix: str = ""):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        colored = (
            f'<span style="color:{TEXT_MUTED};">[{ts}]</span> '
            f'{"<span style=\'color:" + color + ";\'>" + prefix + "</span> " if prefix else ""}'
            f'<span style="color:{color};">{msg}</span>\n'
        )
        log_buffer[0] += colored
        log_pane.set_content(log_buffer[0])
        # auto-scroll via JS
        ui.run_javascript("var el=document.querySelector('.log-pane'); if(el) el.scrollTop=el.scrollHeight;")

    def set_stage(key: str, status: str):
        state["stage_status"][key] = status
        cls_map = {"idle": "pill-idle", "active": "pill-active", "done": "pill-done", "error": "pill-error"}
        icons = {"generate": "⚙", "verify": "✔", "review": "🔍", "deploy": "🚀"}
        _, label = STAGES[STAGE_INDEX[key]]
        icon = icons[key]
        if status == "active":
            spinner = ' <span style="animation:spin 1s linear infinite;display:inline-block;">↻</span>'
        else:
            spinner = ""
        pill_refs[key].set_content(
            f'<span class="stage-pill {cls_map[status]}">{icon} {label}{spinner}</span>'
        )
        # update progress bar
        done_count = sum(1 for s in state["stage_status"].values() if s == "done")
        progress_bar.set_value(done_count / len(STAGES))

    def reset_stages():
        for key, _ in STAGES:
            set_stage(key, "idle")
        progress_bar.set_value(0)
        log_buffer[0] = ""
        log_pane.set_content("")
        rule_pane.set_content('<span style="color:#555;">Awaiting generation…</span>')
        deploy_panel.style("display:none;")
        scan_panel.style("display:none;")

    # ── pipeline orchestrator ───────────────────────────────────────────────

    pipeline_task = [None]  # mutable ref to asyncio Task

    async def pipeline():
        state["running"] = True
        run_btn.visible  = False
        stop_btn.visible = True
        reset_stages()

        prompt = prompt_input.value.strip()
        if not prompt:
            log("No description provided. Aborting.", color=DANGER)
            state["running"] = False
            run_btn.visible  = True
            stop_btn.visible = False
            return

        # ── Stage 1: Generate ─────────────────────────────────────────────
        set_stage("generate", "active")
        log("Starting rule generation…", color=ACCENT, prefix="GEN")

        if BACKEND_AVAILABLE:
            q: asyncio.Queue = asyncio.Queue()
            log(f"[DBG] Dispatching to _llm_generate (LLM1)…", color=TEXT_MUTED, prefix="DBG")
            print("[DEBUG] About to call run.io_bound(_llm_generate, LLM1)", flush=True)
            yara_rule = await run.io_bound(_llm_generate, prompt, "LLM1", q)
            print(f"[DEBUG] run.io_bound returned. yara_rule length: {len(yara_rule) if yara_rule else 0}", flush=True)
            log(f"[DBG] _llm_generate returned {len(yara_rule) if yara_rule else 0} chars.", color=TEXT_MUTED, prefix="DBG")
            # Check queue for any errors emitted during generation
            while not q.empty():
                msg_type, payload = q.get_nowait()
                if msg_type == "error":
                    log(f"LLM error: {payload}", color=DANGER)
                    set_stage("generate", "error")
                    return
            if not yara_rule:
                log("Model returned an empty response.", color=DANGER)
                set_stage("generate", "error")
                return
        else:
            # Demo stub
            await asyncio.sleep(1.5)
            yara_rule = _demo_rule(prompt)

        if not state["running"]:
            log("Stopped by user.", color=WARNING)
            return

        rule_pane.set_content(f"<pre>{yara_rule}</pre>")
        set_stage("generate", "done")
        log("Rule generated.", color=SUCCESS, prefix="GEN")

        # ── Stage 2: Verify ───────────────────────────────────────────────
        set_stage("verify", "active")
        log("Running YARAC syntax verification…", color=ACCENT, prefix="VERIFY")

        for attempt in range(1, (LP.RETRIES if BACKEND_AVAILABLE else 3) + 1):
            if not state["running"]:
                log("Stopped by user.", color=WARNING)
                return

            if BACKEND_AVAILABLE:
                retcode, result_obj = await run.io_bound(yarac, yara_rule)
            else:
                await asyncio.sleep(0.6)
                retcode, result_obj = _demo_verify(yara_rule, attempt)

            if retcode == 0:
                log(f"Syntax OK (attempt {attempt}).", color=SUCCESS, prefix="VERIFY")
                set_stage("verify", "done")
                break
            else:
                log(f"Attempt {attempt}: syntax error detected.", color=WARNING, prefix="VERIFY")
                err_text = str(result_obj)
                fix_prompt = (
                    f"The following YARA ruleset contains errors identified by the YARA compiler, YARAC. "
                    f"Look at information provided by YARAC, and alter the rule accordingly.\n "
                    f"YARAC OUTPUT:\n{err_text}.\nRULES THAT YARAC TESTED:\n {yara_rule}"
                )
                if BACKEND_AVAILABLE:
                    q2: asyncio.Queue = asyncio.Queue()
                    yara_rule = await run.io_bound(_llm_generate, fix_prompt, "LLM1", q2, True)
                else:
                    await asyncio.sleep(0.4)
                    yara_rule = _demo_rule(prompt)  # pretend it was fixed
                rule_pane.set_content(f"<pre>{yara_rule}</pre>")
        else:
            log(f"Syntax verification failed after {LP.RETRIES if BACKEND_AVAILABLE else 3} attempts.", color=DANGER)
            set_stage("verify", "error")
            state["running"] = False
            run_btn.visible  = True
            stop_btn.visible = False
            return

        # ── Stage 3: Review ───────────────────────────────────────────────
        set_stage("review", "active")
        log("Sending rule to Reviewer LLM…", color=ACCENT, prefix="REVIEW")

        if BACKEND_AVAILABLE:
            q3: asyncio.Queue = asyncio.Queue()
            review_text = await run.io_bound(_llm_generate, yara_rule, "LLM2", q3)
        else:
            await asyncio.sleep(1.2)
            review_text = "✔ Rule looks well-formed. No obvious logic errors detected. Coverage appears appropriate for the described threat."

        log(f"Reviewer: {review_text[:300]}{'…' if len(review_text) > 300 else ''}", color=TEXT_MAIN, prefix="REVIEW")
        set_stage("review", "done")

        # Surface deploy panel
        state["final_rule"] = yara_rule
        deploy_panel.style("display:block;")

        # ── Scan uploads if any ───────────────────────────────────────────
        if state["uploads"]:
            log(f"Running scan on {len(state['uploads'])} uploaded file(s)…", color=ACCENT, prefix="SCAN")
            scan_panel.style("display:block;")
            scan_results_container.clear()

            with tempfile.TemporaryDirectory() as tmpdir:
                # write rule
                rule_path = os.path.join(tmpdir, "sentinel_temp.yar")
                with open(rule_path, "w") as rf:
                    rf.write(yara_rule)
                # write uploaded files
                samples_dir = os.path.join(tmpdir, "samples")
                os.makedirs(samples_dir)
                for fname, fbytes in state["uploads"]:
                    with open(os.path.join(samples_dir, fname), "wb") as sf:
                        sf.write(fbytes)

                if BACKEND_AVAILABLE:
                    results = await run.io_bound(deployer_scan, "sentinel_temp.yar", samples_dir)
                else:
                    results = _demo_scan(state["uploads"])

            with scan_results_container:
                if not results:
                    ui.html('<div class="scan-result scan-clean">✔ No matches — all files clean.</div>')
                    log("Scan complete. No matches.", color=SUCCESS, prefix="SCAN")
                else:
                    for filepath, rules in results.items():
                        rule_names = ", ".join(r.identifier for r in rules) if hasattr(rules[0], "identifier") else str(rules)
                        ui.html(
                            f'<div class="scan-result scan-hit">'
                            f'⚠ <strong>{os.path.basename(filepath)}</strong> → {rule_names}'
                            f'</div>'
                        )
                        log(f"HIT: {filepath} → {rule_names}", color=DANGER, prefix="SCAN")

        stop_btn.visible = False
        run_btn.visible  = True
        state["running"] = False
        ui.notify("Pipeline complete — review and deploy when ready.", color="positive", timeout=5000)

    def start_pipeline():
        if state["running"]:
            return
        task = asyncio.ensure_future(pipeline())
        pipeline_task[0] = task

    def stop_pipeline():
        state["running"] = False
        stop_btn.visible = False
        run_btn.visible  = True
        log("Pipeline stopped by user.", color=WARNING)
        for key, _ in STAGES:
            if state["stage_status"][key] == "active":
                set_stage(key, "error")

    # ── deploy / reject ────────────────────────────────────────────────────

    def do_deploy():
        rule = state["final_rule"]
        if not rule:
            ui.notify("No rule to deploy.", color="negative")
            return
        RULES_DIR.mkdir(exist_ok=True)
        filename = f"Sentinel_Rule-{datetime.datetime.now():%Y%m%d_%H%M%S}.yar"
        out = RULES_DIR / filename
        out.write_text(rule)
        set_stage("deploy", "done")
        deploy_panel.style("display:none;")
        log(f"Rule saved → {out}", color=SUCCESS, prefix="DEPLOY")
        ui.notify(f"Deployed: {filename}", color="positive", timeout=6000)

    def do_reject():
        deploy_panel.style("display:none;")
        set_stage("deploy", "error")
        log("Rule rejected by operator.", color=DANGER, prefix="DEPLOY")
        ui.notify("Rule rejected.", color="negative")

    # ── demo stubs (used when backend not available) ───────────────────────

    def _demo_rule(prompt: str) -> str:
        return (
            'rule Sentinel_Demo\n'
            '{\n'
            '    meta:\n'
            f'        description = "Auto-generated rule for: {prompt[:60]}"\n'
            '        author      = "Sentinel"\n'
            f'        date        = "{datetime.date.today()}"\n'
            '\n'
            '    strings:\n'
            '        $s1 = "malware_string" ascii nocase\n'
            '        $s2 = { 4D 5A 90 00 }\n'
            '\n'
            '    condition:\n'
            '        uint16(0) == 0x5A4D and any of them\n'
            '}\n'
        )

    def _demo_verify(rule: str, attempt: int):
        # Fail on first attempt to demo the retry loop
        if attempt == 1:
            class FakeResult:
                returncode = 1
                stderr = "error: line 5: syntax error, unexpected $end"
            return 1, FakeResult()
        return 0, None

    def _demo_scan(uploads):
        # Return a fake hit on the first file for demo purposes
        return {}


ui.run(
    title="Sentinel — YARA Rule Generator",
    favicon="🛡",
    dark=True,
    port=8080,
    reload=False,
)