# Text for the openwebui.com community listing

Copy the parts below into the form at openwebui.com → Functions → Create.

**Name:** Wazuh-Analyse

**Type:** Pipe

**Short description:**
Rule-based triage of Wazuh vulnerability findings on Debian/Ubuntu – traffic-light verdict, reasons and the exact commands to verify. Works without an LLM. Output in German.

**Description:**

> 🇩🇪 **Note: All answers of this function are in German.** The verdict uses emoji (🟢 🟡 🔴) and standard shell commands, so it stays readable without German; the explanations are German only.

Paste a document from `wazuh-states-vulnerabilities-*` (JSON) into the chat and get a clear verdict:

- 🟢 no action needed · 🟡 unclear, please check · 🔴 action needed
- why, in plain language
- the exact read-only commands to run on that host

Paste the command output into the same chat and the function gives the final result: affected yes/no, reachable from outside yes/no, what to do.

Wazuh reports lots of "Package default status" findings on Debian that are not real problems: Debian backported the fix without changing the version, the affected kernel driver is not loaded, or the bug is local-only. Small local LLMs get version comparisons and rules wrong, large ones are slow. So all rules are implemented in Python; the LLM only writes one optional "what is this about" sentence. Answers take about a second.

What it checks:
- Version ranges from the description ("before", "through", "X to before Y", "from X until Y", lists, "fixed in"), Debian epochs, `+really` versions, Debian backport suffixes (never 🔴 while a backport is possible)
- Kernel findings (since 2.0, data-driven): affected source files and version ranges from kernel.org (via CVE.org), then the kernel Makefiles map the file to the exact config symbol and module (`drivers/gpu/drm/xe/xe_bo.c` → `CONFIG_DRM_XE` → module `xe`). The check command greps exactly that symbol and module. Foreign architecture, bug introduced in a newer kernel, or fix already installed → 🟢 right away; module present but not loaded → 🟢; auto-loadable network modules → 🟡
- After pasting the output: Debian changelog and a generic network check – which processes with a listening socket belong to the package or have its libraries mapped (`/proc/PID/maps`, no hard-coded port list). Plus local-only and client-side bugs, Secure Boot (`mokutil`), programs using a library

Settings (valves): `LLM_URL` (any OpenAI-compatible API: llama.cpp, Ollama, vLLM, OpenAI), `LLM_KEY`, `LLM_MODELL`, `WORUM_SATZ` (off = no LLM at all), `ONLINE` (query NVD and CVE.org for the attack vector, the Debian security tracker for the fix status and, for kernel findings, the kernel Makefiles on GitHub; needs internet access from the Open WebUI container — type `Verbindungstest` in the chat to check), `NVD_KEY` (optional).

Tested setup: RTX 3060 Ti 8 GB, Ryzen 7 3700X, 32 GB RAM, Debian 13, llama.cpp `llama-server` with Qwen3.5-9B (Unsloth UD-Q4_K_XL, fully on GPU), Open WebUI 0.13.0, Wazuh 4.14.10 – about 1 second per answer. Any small model (3–4B, even CPU-only) is enough for the single sentence; the verdict itself needs no LLM. For comparison: as a pure system prompt the same 9B model with thinking took ~35 s per finding and was still not always right.

Limitations: Debian/Ubuntu agents only, vulnerability state documents only (no alerts), heuristic text parsing. **Output is in German.** A 🟢 is a well-founded assessment, not a guarantee.

Developed by Elwin Ehlers with Claude (Anthropic). Tested with Open WebUI 0.13.0. Source, examples and tests: https://github.com/ElwinEhlers/wazuh-openwebui
