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
- Kernel findings: extracts the driver ("drm/xe:" → xe), foreign architectures (s390, arm …) → 🟢, checks kernel config and `lsmod` (module present but not loaded → 🟢)
- After pasting the output: Debian changelog, listening ports of known services, local-only and client-side bugs, Secure Boot (`mokutil`), libraries → programs using them, old CVEs → Debian tracker

Settings (valves): `LLM_URL` (any OpenAI-compatible API: llama.cpp, Ollama, vLLM, OpenAI), `LLM_KEY`, `LLM_MODELL`, `WORUM_SATZ` (off = no LLM at all), `ONLINE` (query NVD for the attack vector and the Debian security tracker for the fix status; needs internet access from the Open WebUI container — type `Verbindungstest` in the chat to check), `NVD_KEY` (optional).

Tested setup: RTX 3060 Ti 8 GB, Ryzen 7 3700X, 32 GB RAM, Debian 13, llama.cpp `llama-server` with Qwen3.5-9B (Unsloth UD-Q4_K_XL, fully on GPU), Open WebUI 0.13.0, Wazuh 4.14.10 – about 1 second per answer. Any small model (3–4B, even CPU-only) is enough for the single sentence; the verdict itself needs no LLM. For comparison: as a pure system prompt the same 9B model with thinking took ~35 s per finding and was still not always right.

Limitations: Debian/Ubuntu agents only, vulnerability state documents only (no alerts), heuristic text parsing. **Output is in German.** A 🟢 is a well-founded assessment, not a guarantee.

Developed by Elwin Ehlers with Claude (Anthropic). Tested with Open WebUI 0.13.0. Source, examples and tests: https://github.com/ElwinEhlers/wazuh-openwebui
