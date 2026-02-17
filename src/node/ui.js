const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>LOOM Live Console</title>
    <style>
      :root {
        --bg-top: #f8efe0;
        --bg-bottom: #f4f7f2;
        --ink-strong: #102018;
        --ink: #2c4136;
        --muted: #5f7167;
        --card: rgba(255, 255, 255, 0.82);
        --card-border: rgba(16, 32, 24, 0.12);
        --accent: #0f766e;
        --accent-alt: #c2410c;
        --danger: #9f1239;
        --ok: #166534;
        --shadow: 0 20px 35px rgba(32, 52, 44, 0.12);
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        min-height: 100vh;
        color: var(--ink);
        font-family: "Space Grotesk", "Avenir Next", "Trebuchet MS", sans-serif;
        background:
          radial-gradient(circle at 10% 15%, rgba(194, 65, 12, 0.18), transparent 35%),
          radial-gradient(circle at 80% 20%, rgba(15, 118, 110, 0.16), transparent 30%),
          linear-gradient(160deg, var(--bg-top), var(--bg-bottom));
        animation: page-enter 420ms ease-out both;
      }

      .shell {
        width: min(1180px, 94vw);
        margin: 28px auto 36px;
      }

      .hero {
        position: relative;
        overflow: hidden;
        border: 1px solid var(--card-border);
        border-radius: 20px;
        background: linear-gradient(130deg, rgba(15, 118, 110, 0.94), rgba(194, 65, 12, 0.9));
        color: #fffdf7;
        box-shadow: var(--shadow);
        padding: 22px 22px 18px;
      }

      .hero::after {
        content: "";
        position: absolute;
        width: 240px;
        height: 240px;
        border-radius: 999px;
        right: -70px;
        top: -95px;
        background: rgba(255, 255, 255, 0.18);
      }

      .hero h1 {
        margin: 0;
        font-size: clamp(1.35rem, 2vw + 0.8rem, 2rem);
        letter-spacing: 0.02em;
      }

      .hero p {
        margin: 8px 0 14px;
        max-width: 780px;
        color: rgba(255, 250, 243, 0.9);
      }

      .chip {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        font-size: 0.84rem;
        font-weight: 700;
        border-radius: 999px;
        border: 1px solid rgba(255, 255, 255, 0.38);
        padding: 6px 10px;
        background: rgba(16, 32, 24, 0.16);
      }

      .dot {
        width: 8px;
        height: 8px;
        border-radius: 999px;
        background: #fef08a;
        box-shadow: 0 0 0 4px rgba(254, 240, 138, 0.2);
      }

      .controls {
        margin-top: 16px;
        display: grid;
        grid-template-columns: 1fr;
        gap: 10px;
      }

      .control-row {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }

      .control-row input[type="text"] {
        flex: 1 1 340px;
      }

      input[type="text"],
      textarea,
      select,
      button {
        border-radius: 12px;
        border: 1px solid var(--card-border);
        font: inherit;
      }

      input[type="text"],
      textarea,
      select {
        padding: 10px 12px;
        background: rgba(255, 255, 255, 0.9);
        color: var(--ink-strong);
      }

      textarea {
        min-height: 92px;
        resize: vertical;
      }

      button {
        cursor: pointer;
        padding: 10px 12px;
        font-weight: 700;
        color: #fff;
        background: var(--accent);
      }

      button.alt {
        background: var(--accent-alt);
      }

      button.ghost {
        background: rgba(255, 255, 255, 0.2);
        border-color: rgba(255, 255, 255, 0.45);
      }

      button:disabled {
        opacity: 0.65;
        cursor: not-allowed;
      }

      .grid {
        margin-top: 14px;
        display: grid;
        grid-template-columns: repeat(12, 1fr);
        gap: 12px;
      }

      .card {
        border-radius: 16px;
        border: 1px solid var(--card-border);
        background: var(--card);
        box-shadow: var(--shadow);
        padding: 14px;
        animation: card-rise 520ms ease-out both;
      }

      .card:nth-child(2) { animation-delay: 45ms; }
      .card:nth-child(3) { animation-delay: 90ms; }
      .card:nth-child(4) { animation-delay: 135ms; }
      .card:nth-child(5) { animation-delay: 180ms; }
      .card:nth-child(6) { animation-delay: 225ms; }
      .card:nth-child(7) { animation-delay: 270ms; }

      .span-4 { grid-column: span 4; }
      .span-5 { grid-column: span 5; }
      .span-6 { grid-column: span 6; }
      .span-7 { grid-column: span 7; }
      .span-8 { grid-column: span 8; }
      .span-12 { grid-column: span 12; }

      .card h2 {
        margin: 0 0 10px;
        font-size: 0.95rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: var(--ink-strong);
      }

      .mono {
        margin: 0;
        font-family: "IBM Plex Mono", "SF Mono", "Consolas", monospace;
        font-size: 0.8rem;
        line-height: 1.45;
      }

      .muted {
        color: var(--muted);
      }

      .pill-row {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }

      .folder-pill {
        border-radius: 999px;
        padding: 8px 11px;
        border: 1px solid var(--card-border);
        font-size: 0.82rem;
        font-weight: 700;
        color: var(--ink-strong);
        background: rgba(255, 255, 255, 0.8);
      }

      .folder-pill.active {
        color: #ffffff;
        background: var(--accent);
        border-color: transparent;
      }

      .list {
        display: grid;
        gap: 8px;
      }

      .row {
        border: 1px solid rgba(16, 32, 24, 0.1);
        border-radius: 10px;
        padding: 9px 10px;
        background: rgba(255, 255, 255, 0.75);
      }

      .row strong {
        display: block;
        margin-bottom: 2px;
        color: var(--ink-strong);
      }

      .form-grid {
        display: grid;
        gap: 8px;
      }

      .status-line {
        margin-top: 10px;
        font-size: 0.85rem;
      }

      .status-line.ok {
        color: var(--ok);
      }

      .status-line.error {
        color: var(--danger);
      }

      .empty {
        padding: 10px;
        border-radius: 10px;
        color: var(--muted);
        border: 1px dashed rgba(16, 32, 24, 0.2);
      }

      @media (max-width: 1024px) {
        .span-4,
        .span-5,
        .span-6,
        .span-7,
        .span-8 {
          grid-column: span 12;
        }
      }

      @keyframes page-enter {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
      }

      @keyframes card-rise {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
      }
    </style>
  </head>
  <body>
    <main class="shell">
      <section class="hero">
        <h1>LOOM Live Console</h1>
        <p>Live operational view for bridge, gateway, threads, and audit. Paste your bearer token and refresh to inspect traffic.</p>
        <div class="chip"><span class="dot" id="statusDot"></span><span id="statusText">Idle</span></div>
        <div class="controls">
          <div class="control-row">
            <input id="tokenInput" type="text" placeholder="Bearer token (at_...)" autocomplete="off">
          </div>
          <div class="control-row">
            <button id="saveTokenBtn" type="button">Save Token</button>
            <button id="clearTokenBtn" type="button" class="ghost">Clear Token</button>
            <button id="refreshBtn" type="button" class="alt">Refresh Snapshot</button>
          </div>
        </div>
      </section>

      <section class="grid">
        <article class="card span-4">
          <h2>System</h2>
          <p class="mono" id="systemInfo">Loading system status...</p>
        </article>

        <article class="card span-8">
          <h2>Folders</h2>
          <div class="pill-row" id="folderPills"></div>
          <p class="muted mono" id="foldersMeta"></p>
        </article>

        <article class="card span-7">
          <h2>Messages</h2>
          <div class="list" id="messageList"></div>
        </article>

        <article class="card span-5">
          <h2>Threads</h2>
          <div class="list" id="threadList"></div>
        </article>

        <article class="card span-12">
          <h2>Audit</h2>
          <div class="list" id="auditList"></div>
        </article>

        <article class="card span-6">
          <h2>Bridge Inbound</h2>
          <form id="bridgeForm" class="form-grid">
            <input type="text" name="smtp_from" placeholder="External Sender <sender@example.net>" required>
            <input type="text" name="rcpt_to" placeholder="alice@node.test,bob@node.test" required>
            <textarea name="text" placeholder="Raw inbound email body" required></textarea>
            <button type="submit">Create Inbound Envelope</button>
          </form>
          <div id="bridgeStatus" class="status-line muted">Ready.</div>
        </article>

        <article class="card span-6">
          <h2>SMTP Submit</h2>
          <form id="smtpForm" class="form-grid">
            <input type="text" name="to" placeholder="bob@node.test,team@remote.test" required>
            <textarea name="text" placeholder="Outgoing email body" required></textarea>
            <button type="submit" class="alt">Submit Via Gateway</button>
          </form>
          <div id="smtpStatus" class="status-line muted">Ready.</div>
        </article>
      </section>
    </main>

    <script>
      (function () {
        const state = {
          token: localStorage.getItem("loom_live_token") || "",
          folder: "INBOX"
        };

        const statusDot = document.getElementById("statusDot");
        const statusText = document.getElementById("statusText");
        const tokenInput = document.getElementById("tokenInput");
        const saveTokenBtn = document.getElementById("saveTokenBtn");
        const clearTokenBtn = document.getElementById("clearTokenBtn");
        const refreshBtn = document.getElementById("refreshBtn");
        const systemInfo = document.getElementById("systemInfo");
        const folderPills = document.getElementById("folderPills");
        const foldersMeta = document.getElementById("foldersMeta");
        const messageList = document.getElementById("messageList");
        const threadList = document.getElementById("threadList");
        const auditList = document.getElementById("auditList");
        const bridgeForm = document.getElementById("bridgeForm");
        const smtpForm = document.getElementById("smtpForm");
        const bridgeStatus = document.getElementById("bridgeStatus");
        const smtpStatus = document.getElementById("smtpStatus");

        tokenInput.value = state.token;

        function setIndicator(mode, text) {
          statusText.textContent = text;
          if (mode === "ok") {
            statusDot.style.background = "#86efac";
            statusDot.style.boxShadow = "0 0 0 4px rgba(134, 239, 172, 0.25)";
            return;
          }
          if (mode === "error") {
            statusDot.style.background = "#fecaca";
            statusDot.style.boxShadow = "0 0 0 4px rgba(254, 202, 202, 0.3)";
            return;
          }
          statusDot.style.background = "#fef08a";
          statusDot.style.boxShadow = "0 0 0 4px rgba(254, 240, 138, 0.2)";
        }

        function formatIso(value) {
          if (!value) {
            return "n/a";
          }
          const date = new Date(value);
          return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
        }

        function setStatus(target, ok, text) {
          target.textContent = text;
          target.className = "status-line " + (ok ? "ok" : "error");
        }

        function clearWithEmpty(target, message) {
          target.innerHTML = "";
          const empty = document.createElement("div");
          empty.className = "empty mono";
          empty.textContent = message;
          target.appendChild(empty);
        }

        async function api(path, options) {
          const opts = options || {};
          const headers = { "content-type": "application/json" };
          if (opts.auth !== false && state.token) {
            headers.authorization = "Bearer " + state.token;
          }

          const response = await fetch(path, {
            method: opts.method || "GET",
            headers: headers,
            body: opts.body ? JSON.stringify(opts.body) : undefined
          });

          const type = response.headers.get("content-type") || "";
          const payload = type.includes("application/json") ? await response.json() : await response.text();
          if (!response.ok) {
            const message =
              payload && payload.error && payload.error.message
                ? payload.error.message
                : "Request failed (" + response.status + ")";
            throw new Error(message);
          }
          return payload;
        }

        async function loadSystem() {
          const health = await api("/health", { auth: false });
          const node = await api("/.well-known/loom.json", { auth: false });
          systemInfo.textContent =
            "service: " + health.service + "\\n" +
            "time: " + formatIso(health.timestamp) + "\\n" +
            "node_id: " + node.node_id + "\\n" +
            "domain: " + node.domain + "\\n" +
            "version: " + node.version + "\\n" +
            "deliver_url: " + node.endpoints.deliver;
        }

        function renderFolders(folders) {
          folderPills.innerHTML = "";
          if (!Array.isArray(folders) || folders.length === 0) {
            clearWithEmpty(folderPills, "No folders yet.");
            foldersMeta.textContent = "";
            return;
          }

          for (const folder of folders) {
            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = "folder-pill" + (state.folder === folder.name ? " active" : "");
            btn.textContent = folder.name + " (" + folder.count + ")";
            btn.addEventListener("click", function () {
              state.folder = folder.name;
              renderFolders(folders);
              loadMessages().catch(onError);
            });
            folderPills.appendChild(btn);
          }

          foldersMeta.textContent = "Selected folder: " + state.folder;
        }

        function renderMessages(messages) {
          messageList.innerHTML = "";
          if (!Array.isArray(messages) || messages.length === 0) {
            clearWithEmpty(messageList, "No messages in " + state.folder + ".");
            return;
          }

          for (const msg of messages.slice(0, 40)) {
            const row = document.createElement("div");
            row.className = "row mono";

            const title = document.createElement("strong");
            title.textContent = msg.subject || "(no subject)";
            row.appendChild(title);

            const meta = document.createElement("div");
            meta.textContent =
              "from: " + (msg.from || "unknown") +
              " | envelope: " + (msg.envelope_id || "n/a");
            row.appendChild(meta);

            const date = document.createElement("div");
            date.className = "muted";
            date.textContent = formatIso(msg.date);
            row.appendChild(date);

            messageList.appendChild(row);
          }
        }

        function renderThreads(threads) {
          threadList.innerHTML = "";
          if (!Array.isArray(threads) || threads.length === 0) {
            clearWithEmpty(threadList, "No threads yet.");
            return;
          }

          for (const thread of threads.slice(0, 24)) {
            const row = document.createElement("div");
            row.className = "row mono";

            const title = document.createElement("strong");
            title.textContent = thread.subject || thread.id;
            row.appendChild(title);

            const meta = document.createElement("div");
            meta.textContent =
              "state: " + thread.state +
              " | participants: " + (thread.participants ? thread.participants.length : 0);
            row.appendChild(meta);

            const date = document.createElement("div");
            date.className = "muted";
            date.textContent = "updated: " + formatIso(thread.updated_at);
            row.appendChild(date);

            threadList.appendChild(row);
          }
        }

        function renderAudit(entries) {
          auditList.innerHTML = "";
          if (!Array.isArray(entries) || entries.length === 0) {
            clearWithEmpty(auditList, "No audit entries yet.");
            return;
          }

          for (const item of entries.slice(0, 40)) {
            const row = document.createElement("div");
            row.className = "row mono";

            const title = document.createElement("strong");
            title.textContent = item.action || "unknown_action";
            row.appendChild(title);

            const meta = document.createElement("div");
            meta.textContent = "event: " + item.event_id + " | " + formatIso(item.timestamp);
            row.appendChild(meta);

            const payload = document.createElement("div");
            payload.className = "muted";
            payload.textContent = JSON.stringify(item.payload || {});
            row.appendChild(payload);

            auditList.appendChild(row);
          }
        }

        async function loadFolders() {
          if (!state.token) {
            renderFolders([]);
            clearWithEmpty(messageList, "Add token to load mailbox.");
            return;
          }
          const data = await api("/v1/gateway/imap/folders");
          renderFolders(data.folders || []);
        }

        async function loadMessages() {
          if (!state.token) {
            clearWithEmpty(messageList, "Add token to load mailbox.");
            return;
          }
          const data = await api("/v1/gateway/imap/folders/" + encodeURIComponent(state.folder) + "/messages?limit=40");
          renderMessages(data.messages || []);
        }

        async function loadThreads() {
          const data = await api("/v1/threads", { auth: false });
          renderThreads(data.threads || []);
        }

        async function loadAudit() {
          if (!state.token) {
            clearWithEmpty(auditList, "Add token to load audit entries.");
            return;
          }
          const data = await api("/v1/audit?limit=30");
          renderAudit(data.entries || []);
        }

        async function refreshAll() {
          setIndicator("idle", "Refreshing...");
          try {
            await loadSystem();
            await loadFolders();
            await loadMessages();
            await loadThreads();
            await loadAudit();
            setIndicator("ok", "Live");
          } catch (error) {
            setIndicator("error", "Error");
            console.error(error);
          }
        }

        function onError(error) {
          setIndicator("error", "Error");
          console.error(error);
        }

        saveTokenBtn.addEventListener("click", function () {
          state.token = tokenInput.value.trim();
          if (state.token) {
            localStorage.setItem("loom_live_token", state.token);
          } else {
            localStorage.removeItem("loom_live_token");
          }
          refreshAll().catch(onError);
        });

        clearTokenBtn.addEventListener("click", function () {
          state.token = "";
          tokenInput.value = "";
          localStorage.removeItem("loom_live_token");
          refreshAll().catch(onError);
        });

        refreshBtn.addEventListener("click", function () {
          refreshAll().catch(onError);
        });

        bridgeForm.addEventListener("submit", async function (event) {
          event.preventDefault();
          if (!state.token) {
            setStatus(bridgeStatus, false, "Token required.");
            return;
          }
          const form = new FormData(bridgeForm);
          const payload = {
            smtp_from: String(form.get("smtp_from") || "").trim(),
            rcpt_to: String(form.get("rcpt_to") || "")
              .split(",")
              .map(function (item) { return item.trim(); })
              .filter(Boolean),
            text: String(form.get("text") || "")
          };
          try {
            const result = await api("/v1/bridge/email/inbound", {
              method: "POST",
              body: payload
            });
            setStatus(bridgeStatus, true, "Accepted " + result.envelope_id);
            await refreshAll();
          } catch (error) {
            setStatus(bridgeStatus, false, error.message);
          }
        });

        smtpForm.addEventListener("submit", async function (event) {
          event.preventDefault();
          if (!state.token) {
            setStatus(smtpStatus, false, "Token required.");
            return;
          }
          const form = new FormData(smtpForm);
          const payload = {
            to: String(form.get("to") || "")
              .split(",")
              .map(function (item) { return item.trim(); })
              .filter(Boolean),
            text: String(form.get("text") || "")
          };
          try {
            const result = await api("/v1/gateway/smtp/submit", {
              method: "POST",
              body: payload
            });
            setStatus(smtpStatus, true, "Submitted " + result.envelope_id);
            state.folder = "Sent";
            await refreshAll();
          } catch (error) {
            setStatus(smtpStatus, false, error.message);
          }
        });

        refreshAll().catch(onError);
        window.setInterval(function () {
          refreshAll().catch(onError);
        }, 6000);
      })();
    </script>
  </body>
</html>`;

export function renderDashboardHtml() {
  return DASHBOARD_HTML;
}
