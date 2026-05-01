import asyncio
import datetime
from pathlib import Path
from nicegui import ui
import sys

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / "backend"))

from backend.LanguageProcessor import call_model, syntax_verification, BASE_DIR as LP_BASE_DIR
from backend import Deployer

# ── Global state ──────────────────────────────────────────────────────────────
log_lines: list[str] = []
log_container = None          # set after UI build
progress_bar = None           # set after UI build
progress_label = None         # set after UI build
description_input = None
scan_dir_input = None



def append_log(msg: str, client: Client = None):
    log_lines.append(msg)
    if log_container is None:
        return
    prefix_color = {
        "[SUCCESS]": "#4ade80", "[ERROR]": "#f87171", "[SEARCH]": "#60a5fa",
        "[TOOL]": "#facc15", "[REVIEW]": "#c084fc", "[INPUT]": "#60a5fa",
        "[SAVE]": "#94a3b8", "[RESULTS]": "#34d399", "[WARNING]": "#fb923c",
    }
    color = "#94a3b8"
    for emoji, c in prefix_color.items():
        if msg.startswith(emoji):
            color = c
            break
    with log_container:
        ui.label(msg).style(
            f"font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; "
            f"color: {color}; padding: 1px 0; white-space: pre-wrap; word-break: break-all;"
        )
    if client:
        client.run_javascript(
            "var el = document.getElementById('log-scroll');"
            "if(el) el.scrollTop = el.scrollHeight;"
        )


def set_progress(pct: int, label: str = ""):
    if progress_bar is not None:
        progress_bar.value = pct / 100
    if progress_label is not None and label:
        progress_label.text = label


async def run_pipeline(client: Client):
    with client:
        log_lines.clear()
        if log_container is not None:
            log_container.clear()

        set_progress(0, "Initialising…")
        progress_bar.visible = True
        progress_label.visible = True

        desc = description_input.value.strip()
        if not desc:
            append_log("[ERROR] Description is required.", client)
            set_progress(0, "")
            return

        append_log("[INPUT] Description received — starting pipeline", client)
        set_progress(10, "Generating YARA rule…")

        append_log("[SEARCH] Calling generator…", client)
        try:
            yara_rule = await asyncio.to_thread(call_model, desc, "LLM1", False)
        except Exception as exc:
            append_log(f"[ERROR] Generation error: {exc}", client)
            set_progress(0, "")
            return

        append_log("[SUCCESS] Rule generated", client)
        set_progress(30, "Verifying syntax…")

        append_log("[TOOL] Running yarac syntax verification…", client)
        verified, fixed_rule = await asyncio.to_thread(syntax_verification, yara_rule)
        if not verified:
            append_log("[ERROR] Verification failed after max retries — aborting.", client)
            set_progress(0, "")
            return

        append_log("[SUCCESS] Syntax verified", client)
        set_progress(60, "Reviewing rule…")

        append_log("[REVIEW] Calling reviewer…", client)
        try:
            review = await asyncio.to_thread(call_model, fixed_rule, "LLM2", False)
        except Exception as exc:
            append_log(f"[ERROR] Review model error: {exc}", client)
            set_progress(0, "")
            return

        append_log("[SUCCESS] Review complete", client)
        set_progress(80, "Writing rule file…")

        rule_name = f"Sentinel_Rule-{datetime.datetime.now():%Y%m%d_%H%M%S}.yar"
        rules_dir = BASE_DIR / "rules"
        rules_dir.mkdir(exist_ok=True)
        rule_path = rules_dir / rule_name
        rule_path.write_text(fixed_rule, encoding="utf-8")
        append_log(f"[SAVE] Rule saved → {rule_path}", client)
        set_progress(90, "Scanning…")

        scan_dir = scan_dir_input.value.strip()
        if scan_dir:
            append_log(f"[SEARCH] Scanning: {scan_dir}", client)
            try:
                results = await asyncio.to_thread(Deployer.scan, rule_name, scan_dir)
                append_log("[RESULTS] Scan results:", client)
                append_log(str(results), client)
            except Exception as exc:
                append_log(f"[ERROR] Scan failed: {exc}", client)
        else:
            append_log("[WARNING] No scan directory — skipping scan step", client)

        set_progress(100, "Pipeline complete")
        append_log("[SUCCESS] Pipeline finished successfully", client)       


# ── Global styles ─────────────────────────────────────────────────────────────
ui.add_head_html("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:        #0a0c10;
    --panel:     #0f1218;
    --border:    #1e2433;
    --accent:    #00d4ff;
    --accent2:   #7c3aed;
    --text:      #cdd6f4;
    --muted:     #4a5568;
    --success:   #4ade80;
    --danger:    #f87171;
    --warning:   #facc15;
  }

  body, .nicegui-content {
    background: var(--bg) !important;
    font-family: 'JetBrains Mono', monospace !important;
    color: var(--text) !important;
    min-height: 100vh;
  }

  /* Kill Quasar defaults */
  .q-field__native, .q-field__input, textarea {
    color: var(--text) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.82rem !important;
  }
  .q-field--outlined .q-field__control {
    background: #0d1117 !important;
    border-color: var(--border) !important;
    border-radius: 4px !important;
  }
  .q-field--outlined.q-field--focused .q-field__control {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 1px var(--accent) !important;
  }
  .q-field__label {
    color: var(--muted) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.72rem !important;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .q-field--focused .q-field__label {
    color: var(--accent) !important;
  }

  /* Progress bar */
  .q-linear-progress__track { background: var(--border) !important; }
  .q-linear-progress__model { background: var(--accent) !important; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  /* Scan result label text */
  .nicegui-label { color: var(--text); }

  /* Upload */
  .q-uploader { background: #0d1117 !important; border: 1px dashed var(--border) !important; border-radius: 4px !important; }
  .q-uploader__header { background: transparent !important; color: var(--muted) !important; }
</style>
""")


# ── Layout ────────────────────────────────────────────────────────────────────
with ui.element("div").style(
    "max-width: 980px; margin: 0 auto; padding: 2.5rem 1.5rem; min-height: 100vh;"
):

    # ── Header ────────────────────────────────────────────────────────────────
    with ui.element("div").style("margin-bottom: 2.5rem;"):
        with ui.element("div").style("display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.4rem;"):
            ui.html(
                '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" '
                'stroke="#00d4ff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">'
                '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>'
            )
            ui.label("Plurilock").style(
                "font-family: 'Syne', sans-serif; font-weight: 800; font-size: 1.6rem; "
                "letter-spacing: 0.2em; color: #ffffff;"
            )
            ui.label("SENTINEL").style(
                "font-family: 'Syne', sans-serif; font-weight: 800; font-size: 1.6rem; "
                "letter-spacing: 0.2em; color: #ff0000;"
            )
        ui.label("Automated threat rule generation").style(
            "font-size: 0.72rem; color: var(--muted); letter-spacing: 0.06em; text-transform: uppercase;"
        )
        ui.element("div").style(
            "margin-top: 1rem; height: 1px; "
            "background: linear-gradient(90deg, #00d4ff 0%, #7c3aed 40%, transparent 100%);"
        )

    # ── Two-column grid ────────────────────────────────────────────────────────
    with ui.element("div").style(
        "display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; margin-bottom: 1.25rem;"
    ):
        # ── Left: inputs ──────────────────────────────────────────────────────
        with ui.element("div").style(
            "background: var(--panel); border: 1px solid var(--border); "
            "border-radius: 6px; padding: 1.5rem; display: flex; flex-direction: column; gap: 1rem;"
        ):
            ui.label("// INPUT PARAMETERS").style(
                "font-size: 0.68rem; letter-spacing: 0.12em; color: #00d4ff; margin-bottom: 0.25rem;"
            )

            description_input = (
                ui.textarea(label="Malware description", placeholder="Describe the malware behaviour, IOCs, or threat characteristics…")
                .props("outlined autogrow rows=6")
                .style("width: 100%;")
            )

            ui.label("Context file (optional)").style(
                "font-size: 0.68rem; letter-spacing: 0.08em; color: var(--muted); text-transform: uppercase;"
            )
            ui.upload(
                label="Drop a sample or context file",
                multiple=False,
                on_upload=lambda e: None,
            ).props("flat").style("width: 100%;")

            scan_dir_input = (
                ui.input(label="Scan directory (optional)", placeholder=str(BASE_DIR))
                .props("outlined")
                .style("width: 100%;")
            )

        # ── Right: status / progress ───────────────────────────────────────────
        with ui.element("div").style(
            "background: var(--panel); border: 1px solid var(--border); "
            "border-radius: 6px; padding: 1.5rem; display: flex; flex-direction: column; gap: 1rem;"
        ):
            ui.label("// PIPELINE STATUS").style(
                "font-size: 0.68rem; letter-spacing: 0.12em; color: #00d4ff; margin-bottom: 0.25rem;"
            )

            # Stage indicators (decorative)
            stages = [
                ("01", "GENERATE", "#00d4ff"),
                ("02", "VERIFY", "#facc15"),
                ("03", "REVIEW", "#c084fc"),
                ("04", "DEPLOY", "#4ade80"),
            ]
            with ui.element("div").style("display: flex; flex-direction: column; gap: 0.5rem;"):
                for num, name, color in stages:
                    with ui.element("div").style(
                        "display: flex; align-items: center; gap: 0.75rem; padding: 0.5rem 0.75rem; "
                        f"border-left: 2px solid {color}22; border-radius: 0 4px 4px 0; "
                        "background: #ffffff04;"
                    ):
                        ui.label(num).style(
                            f"font-size: 0.65rem; color: {color}; letter-spacing: 0.1em; min-width: 1.5rem;"
                        )
                        ui.label(name).style(
                            f"font-size: 0.75rem; color: {color}aa; letter-spacing: 0.1em;"
                        )

            ui.element("div").style("flex: 1;")

            # Progress bar
            with ui.element("div").style("margin-top: 0.5rem;"):
                progress_label = ui.label("Ready").style(
                    "font-size: 0.68rem; color: var(--muted); letter-spacing: 0.08em; "
                    "text-transform: uppercase; margin-bottom: 0.4rem; display: block;"
                )
                progress_label.visible = False

                progress_bar = ui.linear_progress(value=0).props("rounded").style(
                    "height: 4px; border-radius: 2px;"
                )
                progress_bar.visible = False

    # ── Log console ───────────────────────────────────────────────────────────
    with ui.element("div").style(
        "background: #060809; border: 1px solid var(--border); border-radius: 6px; "
        "margin-bottom: 1.25rem; overflow: hidden;"
    ):
        with ui.element("div").style(
            "display: flex; align-items: center; justify-content: space-between; "
            "padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); background: var(--panel);"
        ):
            with ui.element("div").style("display: flex; align-items: center; gap: 0.5rem;"):
                for c in ["#f87171", "#facc15", "#4ade80"]:
                    ui.element("div").style(
                        f"width: 9px; height: 9px; border-radius: 50%; background: {c}44; border: 1px solid {c};"
                    )
                ui.label("console.log").style(
                    "font-size: 0.68rem; color: var(--muted); letter-spacing: 0.08em; margin-left: 0.5rem;"
                )
            ui.label("SENTINEL / v1.0").style("font-size: 0.65rem; color: #1e2433; letter-spacing: 0.08em;")

        with ui.element("div").props('id="log-scroll"').style(
            "height: 220px; overflow-y: auto; padding: 0.85rem 1rem;"
        ):
            log_container = ui.element("div").style("display: flex; flex-direction: column; gap: 0;")
            with log_container:
                ui.label("[ Sentinel ready. Awaiting input. ]").style(
                    "font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; "
                    "color: #2d3748; font-style: italic;"
                )

    # ── Run button ────────────────────────────────────────────────────────────
    with ui.element("div").style("display: flex; justify-content: flex-end;"):
        btn = ui.button(
            "RUN",
            on_click=lambda: asyncio.create_task(run_pipeline(ui.context.client)),
        ).style(
            "background: linear-gradient(135deg, #0ea5e9, #7c3aed) !important; "
            "color: #ffffff !important; font-family: 'JetBrains Mono', monospace !important; "
            "font-size: 0.78rem !important; font-weight: 600 !important; "
            "letter-spacing: 0.14em !important; padding: 0.7rem 2rem !important; "
            "border-radius: 4px !important; border: none !important; cursor: pointer; "
            "text-transform: uppercase !important; box-shadow: 0 0 20px #0ea5e944;"
        )


ui.run(title="Sentinel", port=8081, dark=True)