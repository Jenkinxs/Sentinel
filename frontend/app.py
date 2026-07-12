import argparse
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

## ── Global state ─────────────────────────────────────────────────────────────
log_lines: list[str] = []
log_container = None
progress_bar = None
progress_label = None
description_input = None
scan_dir_input = None
context_content: str | None = None


def append_log(msg: str, client=None):
    log_lines.append(msg)
    if log_container is None:
        return
    prefix_color = {
        "[SUCCESS]": "#1a7d36", "[ERROR]": "#c91d39", "[SEARCH]": "#8b5cf6",
        "[TOOL]": "#d97706", "[REVIEW]": "#c91d39", "[INPUT]": "#4b5563",
        "[SAVE]": "#6b7280", "[RESULTS]": "#1a7d36", "[WARNING]": "#d97706",
    }
    color = "#6b7280"
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


async def run_pipeline(client):
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

        ## Append context file content if provided
        full_desc = desc
        if context_content:
            full_desc = f"{desc}\n\nContext file contents:\n{context_content}"
            append_log("[INPUT] Context file loaded — appended to description", client)

        append_log("[INPUT] Description received — starting pipeline", client)
        set_progress(10, "Generating YARA rule…")

        def ui_logger(msg):
            append_log(msg, client)

        append_log("[SEARCH] Calling generator…", client)
        try:
            yara_rule = await asyncio.to_thread(
                call_model, full_desc, "GENERATOR", False, ui_logger
            )
        except Exception as exc:
            append_log(f"[ERROR] Generation error: {exc}", client)
            set_progress(0, "")
            return

        append_log("[SUCCESS] Rule generated", client)
        set_progress(30, "Verifying syntax…")

        def ui_logger_syntax(msg):
            append_log(msg, client)

        append_log("[TOOL] Running yara_x syntax verification…", client)
        verified, fixed_rule = await asyncio.to_thread(
            syntax_verification, yara_rule, ui_logger_syntax
        )
        if not verified:
            append_log("[ERROR] Verification failed after max retries — aborting.", client)
            set_progress(0, "")
            return

        append_log("[SUCCESS] Syntax verified", client)
        set_progress(60, "Reviewing rule…")

        def ui_logger_review(msg):
            append_log(msg, client)

        append_log("[REVIEW] Calling reviewer…", client)
        try:
            review = await asyncio.to_thread(
                call_model, fixed_rule, "REVIEWER", False, ui_logger_review
            )
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
        append_log(f"[SAVE] Rule saved -> {rule_path}", client)
        set_progress(90, "Scanning…")

        scan_dir = scan_dir_input.value.strip()
        if scan_dir:
            append_log(f"[SEARCH] Scanning: {scan_dir}", client)
            try:
                def ui_logger_deployer(msg):
                    append_log(msg, client)

                results = await asyncio.to_thread(
                    Deployer.scan, rule_name, scan_dir, ui_logger_deployer
                )
                append_log("[RESULTS] Scan results:", client)
                append_log(str(results), client)
            except Exception as exc:
                append_log(f"[ERROR] Scan failed: {exc}", client)
        else:
            append_log("[WARNING] No scan directory — skipping scan step", client)

        set_progress(100, "Pipeline complete")
        append_log("[SUCCESS] Pipeline finished successfully", client)


## ── Global styles ─────────────────────────────────────────────────────────────
ui.add_head_html("""\
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,700;0,900;1,400&family=Lora:ital,wght@0,400;0,500;0,600;1,400&family=JetBrains+Mono:wght@300;400;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:        #f8f5f0;
    --panel:     #ffffff;
    --border:    #e5ddd4;
    --accent:    #c91d39;
    --accent-hover: #a81830;
    --text:      #1a1a1a;
    --muted:     #7d7168;
    --success:   #1a7d36;
    --danger:    #c91d39;
    --warning:   #d97706;
  }

  body, .nicegui-content {
    background: var(--bg) !important;
    font-family: 'Lora', Georgia, 'Times New Roman', serif !important;
    color: var(--text) !important;
    min-height: 100vh;
  }

  .q-field__native, .q-field__input, textarea {
    color: var(--text) !important;
    font-family: 'Lora', Georgia, serif !important;
    font-size: 0.9rem !important;
  }
  .q-field--outlined .q-field__control {
    background: var(--panel) !important;
    border-color: var(--border) !important;
    border-radius: 3px !important;
  }
  .q-field--outlined.q-field--focused .q-field__control {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 1px var(--accent) !important;
  }
  .q-field__label {
    color: var(--muted) !important;
    font-family: 'Lora', Georgia, serif !important;
    font-size: 0.75rem !important;
    font-weight: 500 !important;
    letter-spacing: 0.02em;
  }
  .q-field--focused .q-field__label {
    color: var(--accent) !important;
  }

  .q-linear-progress__track { background: var(--border) !important; }
  .q-linear-progress__model { background: var(--accent) !important; }

  ::-webkit-scrollbar { width: 5px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  .q-uploader {
    background: var(--panel) !important;
    border: 1px dashed var(--border) !important;
    border-radius: 3px !important;
  }
  .q-uploader__header {
    background: transparent !important;
    color: var(--muted) !important;
    font-family: 'Lora', Georgia, serif !important;
  }

  .q-uploader__file {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.78rem !important;
  }
</style>
""")


## ── Layout ────────────────────────────────────────────────────────────────────
with ui.element("div").style(
    "max-width: 980px; margin: 0 auto; padding: 2.5rem 1.5rem; min-height: 100vh;"
):

    ## ── Header ────────────────────────────────────────────────────────────────
    with ui.element("div").style("margin-bottom: 2.5rem;"):
        with ui.element("div").style(
            "display: flex; align-items: baseline; gap: 0.5rem; margin-bottom: 0.3rem;"
        ):
            ui.label("Plurilock").style(
                "font-family: 'Playfair Display', Georgia, serif; font-weight: 900; "
                "font-size: 1.8rem; color: #000000; letter-spacing: -0.01em;"
            )
            ui.label("Sentinel").style(
                "font-family: 'Playfair Display', Georgia, serif; font-style: italic; "
                "font-weight: 400; font-size: 1.8rem; color: #c91d39;"
            )
        ui.label("Automated threat rule generation").style(
            "font-family: 'Lora', Georgia, serif; font-size: 0.8rem; "
            "color: var(--muted); font-style: italic;"
        )
        ui.element("div").style(
            "margin-top: 0.9rem; height: 1px; "
            "background: linear-gradient(90deg, #c91d39 0%, #c91d3944 60%, transparent 100%);"
        )

    ## ── Two-column grid ────────────────────────────────────────────────────────
    with ui.element("div").style(
        "display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; "
        "margin-bottom: 1.25rem;"
    ):
        ## ── Left: inputs ──────────────────────────────────────────────────────
        with ui.element("div").style(
            "background: var(--panel); border: 1px solid var(--border); "
            "border-radius: 4px; padding: 1.5rem; display: flex; "
            "flex-direction: column; gap: 1rem;"
        ):
            ui.label("Input").style(
                "font-family: 'Playfair Display', Georgia, serif; "
                "font-size: 0.7rem; font-weight: 700; letter-spacing: 0.08em; "
                "color: var(--accent); text-transform: uppercase; "
                "margin-bottom: 0.15rem;"
            )

            description_input = (
                ui.textarea(
                    label="Malware description",
                    placeholder="Describe the malware behaviour, IOCs, or threat characteristics..."
                )
                .props("outlined autogrow rows=6")
                .style("width: 100%;")
            )

            ui.label("Context file (optional)").style(
                "font-size: 0.72rem; font-weight: 500; color: var(--muted);"
            )
            ui.upload(
                label="Drop a sample or context file",
                multiple=False,
                on_upload=lambda e: _handle_context_upload(e),
            ).props("flat").style("width: 100%;")

            scan_dir_input = (
                ui.input(label="Scan directory (optional)", placeholder=str(BASE_DIR))
                .props("outlined")
                .style("width: 100%;")
            )

        ## ── Right: status / progress ───────────────────────────────────────────
        with ui.element("div").style(
            "background: var(--panel); border: 1px solid var(--border); "
            "border-radius: 4px; padding: 1.5rem; display: flex; "
            "flex-direction: column; gap: 1rem;"
        ):
            ui.label("Pipeline").style(
                "font-family: 'Playfair Display', Georgia, serif; "
                "font-size: 0.7rem; font-weight: 700; letter-spacing: 0.08em; "
                "color: var(--accent); text-transform: uppercase; "
                "margin-bottom: 0.15rem;"
            )

            stages = [
                ("01", "Generate", "#c91d39"),
                ("02", "Verify", "#c91d39"),
                ("03", "Review", "#c91d39"),
                ("04", "Deploy", "#c91d39"),
            ]
            with ui.element("div").style(
                "display: flex; flex-direction: column; gap: 0.35rem;"
            ):
                for num, name, color in stages:
                    with ui.element("div").style(
                        "display: flex; align-items: center; gap: 0.75rem; "
                        f"padding: 0.45rem 0.75rem; "
                        "border-left: 2px solid var(--border); "
                        "border-radius: 0 3px 3px 0;"
                    ):
                        ui.label(num).style(
                            f"font-family: 'JetBrains Mono', monospace; "
                            f"font-size: 0.6rem; color: {color}; "
                            "letter-spacing: 0.1em; min-width: 1.5rem;"
                        )
                        ui.label(name).style(
                            f"font-family: 'Lora', Georgia, serif; "
                            f"font-size: 0.78rem; color: var(--text); "
                            "letter-spacing: 0.02em;"
                        )

            ui.element("div").style("flex: 1;")

            with ui.element("div").style("margin-top: 0.5rem;"):
                progress_label = ui.label("Ready").style(
                    "font-family: 'Lora', Georgia, serif; "
                    "font-size: 0.7rem; font-style: italic; "
                    "color: var(--muted); margin-bottom: 0.4rem; display: block;"
                )
                progress_label.visible = False

                progress_bar = ui.linear_progress(value=0).style(
                    "height: 3px; border-radius: 2px;"
                )
                progress_bar.visible = False

    ## ── Log console ───────────────────────────────────────────────────────────
    with ui.element("div").style(
        "background: var(--panel); border: 1px solid var(--border); "
        "border-radius: 4px; margin-bottom: 1.25rem; overflow: hidden;"
    ):
        with ui.element("div").style(
            "display: flex; align-items: center; justify-content: space-between; "
            "padding: 0.5rem 1rem; border-bottom: 1px solid var(--border); "
            "background: #faf8f6;"
        ):
            with ui.element("div").style(
                "display: flex; align-items: center; gap: 0.4rem;"
            ):
                for c in ["#c91d39", "#d97706", "#1a7d36"]:
                    ui.element("div").style(
                        f"width: 7px; height: 7px; border-radius: 50%; "
                        f"background: {c}33; border: 1px solid {c};"
                    )
                ui.label("Log").style(
                    "font-family: 'Lora', Georgia, serif; "
                    "font-size: 0.7rem; color: var(--muted); "
                    "letter-spacing: 0.04em; margin-left: 0.3rem;"
                )
            ui.label("Sentinel / v1.0").style(
                "font-family: 'JetBrains Mono', monospace; "
                "font-size: 0.6rem; color: var(--border);"
            )

        with ui.element("div").props('id="log-scroll"').style(
            "height: 220px; overflow-y: auto; padding: 0.75rem 1rem;"
        ):
            log_container = ui.element("div").style(
                "display: flex; flex-direction: column; gap: 0;"
            )
            with log_container:
                ui.label("[ Sentinel ready. Awaiting input. ]").style(
                    "font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; "
                    "color: var(--border); font-style: italic;"
                )

    ## ── Run button ────────────────────────────────────────────────────────────
    with ui.element("div").style("display: flex; justify-content: flex-end;"):
        ui.button(
            "Run Pipeline",
            on_click=lambda: asyncio.create_task(run_pipeline(ui.context.client)),
        ).style(
            "background: #c91d39 !important; "
            "color: #ffffff !important; "
            "font-family: 'Playfair Display', Georgia, serif !important; "
            "font-size: 0.8rem !important; font-weight: 700 !important; "
            "font-style: italic !important; "
            "letter-spacing: 0.03em !important; "
            "padding: 0.6rem 1.8rem !important; "
            "border-radius: 3px !important; "
            "border: none !important; cursor: pointer !important; "
            "box-shadow: 0 1px 3px rgba(201, 29, 57, 0.25); "
            "transition: background 0.15s ease;"
        )


def _handle_context_upload(event):
    """Store uploaded context file content in global state."""
    global context_content
    try:
        content = event.content.read().decode("utf-8")
        context_content = content
        append_log(f"[INPUT] Context file loaded: {event.name} ({len(content)} bytes)")
    except Exception as e:
        append_log(f"[ERROR] Failed to read context file: {e}")


def main():
    parser = argparse.ArgumentParser(description="Sentinel Web UI")
    parser.add_argument(
        "--port", type=int, default=8081,
        help="Port to run the web server on (default: 8081)"
    )
    args = parser.parse_args()

    ui.run(
        title="Sentinel",
        port=args.port,
        dark=False,
        favicon=str(BASE_DIR / "frontend/atomic.png"),
    )


if __name__ == "__main__":
    main()
