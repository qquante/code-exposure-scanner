(() => {
  "use strict";

  const state = {
    token: sessionStorage.getItem("sh_admin_token") || "",
    stats: {},
    candidates: [],
    findings: [],
    notifications: [],
    jobs: [],
    runs: [],
    detectors: [],
    filters: {
      candidates: "all",
      findings: "all",
      notifications: "all",
      jobs: "all",
      detectors: "all",
    },
    refreshing: false,
    timer: null,
    activeView: "overview",
    lastFocused: null,
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const esc = (value) => String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

  const STATUS_LABELS = {
    pending_metadata: "Metadados",
    pending_review: "Em revisão",
    filtered: "Filtrado",
    unavailable: "Indisponível",
    scan_queued: "Scan agendado",
    rejected: "Rejeitado",
    pending: "Pendente",
    running: "Executando",
    completed: "Concluído",
    failed: "Falhou",
    approved: "Aprovado",
    sending: "Enviando",
    sent: "Enviado",
    needs_contact: "Contato manual",
    open: "Aberto",
    notified: "Notificado",
    resolved: "Resolvido",
    false_positive: "Falso positivo",
    accepted_risk: "Risco aceito",
    partial: "Parcial",
  };

  const RISK_LABELS = {
    critical: "Crítico",
    high: "Alto",
    medium: "Médio",
    low: "Baixo",
  };

  function statusPill(status) {
    const safe = String(status || "unknown").replace(/[^a-z_]/g, "");
    return `<span class="status-pill status-${safe}">${esc(STATUS_LABELS[status] || status || "—")}</span>`;
  }

  function riskPill(risk) {
    const safe = String(risk || "low").replace(/[^a-z]/g, "");
    return `<span class="risk-pill risk-${safe}">${esc(RISK_LABELS[risk] || risk || "—")}</span>`;
  }

  function formatDate(value, withTime = true) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return esc(value);
    return new Intl.DateTimeFormat("pt-BR", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
    }).format(date);
  }

  function relativeDate(value) {
    if (!value) return "agora";
    const delta = Date.now() - new Date(value).getTime();
    if (!Number.isFinite(delta)) return "—";
    const mins = Math.max(0, Math.round(delta / 60000));
    if (mins < 1) return "agora";
    if (mins < 60) return `há ${mins} min`;
    const hours = Math.round(mins / 60);
    if (hours < 24) return `há ${hours} h`;
    return `há ${Math.round(hours / 24)} d`;
  }

  function formatSize(kb) {
    if (kb === null || kb === undefined) return "—";
    const number = Number(kb);
    if (number < 1024) return `${number.toLocaleString("pt-BR")} KB`;
    return `${(number / 1024).toLocaleString("pt-BR", { maximumFractionDigits: 1 })} MB`;
  }

  function truncated(value, max = 55) {
    const text = String(value || "");
    return text.length > max ? `${text.slice(0, max - 1)}…` : text;
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Authorization", `Bearer ${state.token}`);
    if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    const response = await fetch(path, { ...options, headers, cache: "no-store" });
    if (response.status === 401) {
      logout("Sua sessão foi recusada pela API. Informe o token novamente.");
      throw new Error("Token administrativo inválido");
    }
    const data = response.status === 204 ? null : await response.json().catch(() => null);
    if (!response.ok) {
      const detail = data?.detail || `Erro HTTP ${response.status}`;
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    return data;
  }

  function setBusy(button, busy, label = "Processando…") {
    if (!button) return;
    if (busy) {
      button.dataset.original = button.innerHTML;
      button.innerHTML = label;
      button.disabled = true;
    } else {
      button.innerHTML = button.dataset.original || button.innerHTML;
      button.disabled = false;
    }
  }

  function toast(title, message = "", type = "success") {
    const item = document.createElement("div");
    item.className = `toast ${type === "error" ? "error" : ""}`;
    item.innerHTML = `<div><strong>${esc(title)}</strong>${message ? `<p>${esc(message)}</p>` : ""}</div>`;
    $("#toast-region").append(item);
    window.setTimeout(() => item.remove(), 4800);
  }

  function showLogin(message = "") {
    $("#app-shell").hidden = true;
    $("#login-gate").hidden = false;
    const error = $("#login-error");
    error.textContent = message;
    error.hidden = !message;
    $("#admin-token").value = "";
    window.setTimeout(() => $("#admin-token").focus(), 50);
  }

  function showApp() {
    $("#login-gate").hidden = true;
    $("#app-shell").hidden = false;
  }

  function logout(message = "") {
    state.token = "";
    sessionStorage.removeItem("sh_admin_token");
    clearInterval(state.timer);
    closeModal();
    showLogin(message);
  }

  async function login(token, button) {
    state.token = token.trim();
    if (!state.token) return;
    setBusy(button, true, "Conectando…");
    try {
      const stats = await api("/stats");
      sessionStorage.setItem("sh_admin_token", state.token);
      state.stats = stats;
      showApp();
      await refreshAll(false);
      startAutoRefresh();
    } catch (error) {
      state.token = "";
      sessionStorage.removeItem("sh_admin_token");
      const box = $("#login-error");
      box.textContent = error.message;
      box.hidden = false;
    } finally {
      setBusy(button, false);
    }
  }

  async function refreshAll(notify = true) {
    if (state.refreshing || !state.token) return;
    state.refreshing = true;
    const button = $("#refresh-button");
    setBusy(button, true, "↻");
    try {
      const [stats, candidates, findings, notifications, jobs, runs, detectors] = await Promise.all([
        api("/stats"),
        api("/candidates?limit=500"),
        api("/findings?limit=500"),
        api("/notifications?limit=500"),
        api("/jobs?limit=500"),
        api("/runs?limit=500"),
        api("/detectors"),
      ]);
      Object.assign(state, { stats, candidates, findings, notifications, jobs, runs, detectors });
      renderAll();
      $("#last-refresh").textContent = new Intl.DateTimeFormat("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date());
      if (notify) toast("Dados atualizados", "API e PostgreSQL responderam normalmente.");
    } catch (error) {
      toast("Falha ao atualizar", error.message, "error");
      $("#system-state-detail").textContent = "Falha na leitura administrativa";
    } finally {
      state.refreshing = false;
      setBusy(button, false);
    }
  }

  function startAutoRefresh() {
    clearInterval(state.timer);
    if (!$("#auto-refresh").checked || !state.token) return;
    state.timer = window.setInterval(() => refreshAll(false), 30000);
  }

  function updateBadge(selector, value) {
    const badge = $(selector);
    badge.textContent = String(value || 0);
    badge.hidden = !value;
  }

  function renderAll() {
    renderOverview();
    renderCandidates();
    renderFindings();
    renderNotifications();
    renderJobs();
    renderRuns();
    renderDetectors();
  }

  function renderOverview() {
    const stats = state.stats;
    const candidateReviews = Number(stats.pending_candidate_reviews || 0);
    const activeJobs = Number(stats.pending_jobs || 0) + Number(stats.running_jobs || 0);
    $("#metric-candidates").textContent = candidateReviews.toLocaleString("pt-BR");
    $("#metric-findings").textContent = Number(stats.open_findings || 0).toLocaleString("pt-BR");
    $("#metric-jobs").textContent = activeJobs.toLocaleString("pt-BR");
    $("#metric-notifications").textContent = Number(stats.pending_reviews || 0).toLocaleString("pt-BR");
    $("#system-state-detail").textContent = activeJobs ? `${activeJobs} job(s) ativo(s)` : "API e banco respondendo";
    updateBadge("#nav-candidate-count", candidateReviews);
    updateBadge("#nav-finding-count", stats.open_findings);
    updateBadge("#nav-notification-count", stats.pending_reviews);

    const activities = [
      ...state.candidates.map((item) => ({ kind: "candidate", title: item.repository, description: `Candidato · ${STATUS_LABELS[item.status] || item.status}`, date: item.updated_at || item.first_seen, icon: "◇" })),
      ...state.findings.map((item) => ({ kind: "finding", title: item.repository, description: `${RISK_LABELS[item.risk] || item.risk} · ${item.platform}`, date: item.last_seen, icon: "!" })),
      ...state.runs.map((item) => ({ kind: "run", title: item.scope, description: `Execução ${item.mode} · ${STATUS_LABELS[item.status] || item.status}`, date: item.started_at, icon: "↻" })),
      ...state.notifications.map((item) => ({ kind: "notification", title: item.repository, description: `Alerta · ${STATUS_LABELS[item.status] || item.status}`, date: item.updated_at, icon: "↗" })),
    ].sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0)).slice(0, 5);

    const container = $("#activity-list");
    if (!activities.length) {
      container.innerHTML = `<div class="empty-mini"><div><span>⌁</span><p>Nenhuma atividade registrada.<br>O sistema está pronto para receber eventos e scans autorizados.</p></div></div>`;
      return;
    }
    container.innerHTML = activities.map((item) => `
      <div class="activity-item">
        <span class="activity-icon">${esc(item.icon)}</span>
        <div><strong title="${esc(item.title)}">${esc(truncated(item.title, 64))}</strong><p>${esc(item.description)}</p></div>
        <time>${esc(relativeDate(item.date))}</time>
      </div>`).join("");
  }

  function filteredCandidates() {
    const filter = state.filters.candidates;
    const query = $("#candidate-search").value.trim().toLowerCase();
    return state.candidates.filter((item) => (filter === "all" || item.status === filter) && (!query || String(item.repository).toLowerCase().includes(query)));
  }

  function renderCandidates() {
    const rows = filteredCandidates();
    const body = $("#candidate-table");
    body.innerHTML = rows.map((item) => {
      const canReview = item.status === "pending_review";
      const canReject = ["pending_metadata", "pending_review"].includes(item.status);
      return `<tr>
        <td class="repo-cell"><strong>${esc(item.repository)}</strong><small class="mono">GH #${esc(item.github_repository_id)}</small></td>
        <td>${statusPill(item.status)}${item.filter_reason ? `<small class="secondary-cell">${esc(item.filter_reason)}</small>` : ""}</td>
        <td>${esc(item.language || "Não identificado")}</td>
        <td>${esc(formatSize(item.size_kb))}</td>
        <td><span class="primary-cell">${esc(formatDate(item.event_created_at))}</span><small class="secondary-cell">${esc(relativeDate(item.event_created_at))}</small></td>
        <td><div class="row-actions">
          <button class="row-action" data-action="candidate-detail" data-id="${Number(item.id)}">Detalhes</button>
          ${canReview ? `<button class="row-action primary" data-action="candidate-authorize" data-id="${Number(item.id)}">Autorizar</button>` : ""}
          ${canReject ? `<button class="row-action danger" data-action="candidate-reject" data-id="${Number(item.id)}">Rejeitar</button>` : ""}
        </div></td>
      </tr>`;
    }).join("");
    $("#candidate-empty").hidden = rows.length > 0;
    body.parentElement.hidden = rows.length === 0;
  }

  function filteredFindings() {
    const filter = state.filters.findings;
    const query = $("#finding-search").value.trim().toLowerCase();
    return state.findings.filter((item) => {
      const matchesFilter = filter === "all" || item.risk === filter || item.status === filter;
      const haystack = `${item.repository} ${item.platform} ${item.type_id}`.toLowerCase();
      return matchesFilter && (!query || haystack.includes(query));
    });
  }

  function renderFindings() {
    const rows = filteredFindings();
    const body = $("#finding-table");
    body.innerHTML = rows.map((item) => `<tr>
      <td>${riskPill(item.risk)}</td>
      <td class="repo-cell"><strong>${esc(item.repository)}</strong><small>${statusPill(item.status)}</small></td>
      <td><span class="primary-cell">${esc(item.platform)}</span><small class="secondary-cell mono">${esc(item.type_id)}</small></td>
      <td>${esc(item.environment || "unknown")}</td>
      <td>${statusPill(item.validation_status || "not_checked")}</td>
      <td><span class="primary-cell">${Number(item.location_count || 0)}</span><small class="secondary-cell">localização(ões)</small></td>
      <td><div class="row-actions"><button class="row-action primary" data-action="finding-detail" data-id="${Number(item.id)}">Abrir</button></div></td>
    </tr>`).join("");
    $("#finding-empty").hidden = rows.length > 0;
    body.parentElement.hidden = rows.length === 0;
  }

  function filteredNotifications() {
    const filter = state.filters.notifications;
    return state.notifications.filter((item) => filter === "all" || item.status === filter);
  }

  function renderNotifications() {
    const rows = filteredNotifications();
    const body = $("#notification-table");
    body.innerHTML = rows.map((item) => {
      const actions = [`<button class="row-action" data-action="notification-detail" data-id="${Number(item.id)}">Revisar</button>`];
      if (item.status === "pending_review") {
        actions.push(`<button class="row-action primary" data-action="notification-approve" data-id="${Number(item.id)}">Aprovar</button>`);
        actions.push(`<button class="row-action danger" data-action="notification-reject" data-id="${Number(item.id)}">Rejeitar</button>`);
      } else if (["rejected", "failed", "needs_contact", "sending"].includes(item.status)) {
        actions.push(`<button class="row-action primary" data-action="notification-requeue" data-id="${Number(item.id)}">Reenfileirar</button>`);
      }
      return `<tr>
        <td class="repo-cell"><strong>${esc(item.repository)}</strong><small>#${Number(item.id)}</small></td>
        <td>${esc(item.channel === "private_report" ? "Relato privado" : "Contato público")}</td>
        <td>${statusPill(item.status)}</td>
        <td>${esc(formatDate(item.created_at))}</td>
        <td>${esc(item.approved_by || "—")}</td>
        <td><div class="row-actions">${actions.join("")}</div></td>
      </tr>`;
    }).join("");
    $("#notification-empty").hidden = rows.length > 0;
    body.parentElement.hidden = rows.length === 0;
  }

  function filteredJobs() {
    const filter = state.filters.jobs;
    return state.jobs.filter((item) => filter === "all" || item.status === filter);
  }

  function renderJobs() {
    const rows = filteredJobs();
    const body = $("#job-table");
    body.innerHTML = rows.map((item) => `<tr>
      <td class="mono">#${Number(item.id)}</td>
      <td><span class="primary-cell mono">${esc(item.kind)}</span><small class="secondary-cell">prioridade ${Number(item.priority || 0)}</small></td>
      <td>${statusPill(item.status)}</td>
      <td>${Number(item.attempts || 0)} / ${Number(item.max_attempts || 0)}</td>
      <td><span class="primary-cell mono">${esc(item.lease_owner || "—")}</span><small class="secondary-cell">${esc(item.leased_until ? formatDate(item.leased_until) : "sem lease")}</small></td>
      <td>${esc(formatDate(item.updated_at))}</td>
      <td><div class="row-actions"><button class="row-action" data-action="job-detail" data-id="${Number(item.id)}">Detalhes</button></div></td>
    </tr>`).join("");
    $("#job-empty").hidden = rows.length > 0;
    body.parentElement.hidden = rows.length === 0;
  }

  function renderRuns() {
    const rows = state.runs;
    const body = $("#run-table");
    body.innerHTML = rows.map((item) => `<tr>
      <td class="mono">#${Number(item.id)}</td>
      <td><span class="primary-cell">${esc(item.mode)}</span></td>
      <td class="repo-cell"><strong>${esc(truncated(item.scope, 75))}</strong><small title="${esc(item.scope)}">${esc(item.scope)}</small></td>
      <td>${statusPill(item.status)}</td>
      <td>${Number(item.jobs_created || 0)}</td>
      <td>${Number(item.findings_created || 0)}</td>
      <td>${Number(item.errors || 0)}</td>
      <td><span class="primary-cell">${esc(formatDate(item.started_at))}</span><small class="secondary-cell">${esc(item.finished_at ? formatDate(item.finished_at) : "em aberto")}</small></td>
    </tr>`).join("");
    $("#run-empty").hidden = rows.length > 0;
    body.parentElement.hidden = rows.length === 0;
  }

  function filteredDetectors() {
    const filter = state.filters.detectors;
    const query = $("#detector-search").value.trim().toLowerCase();
    return state.detectors.filter((item) => {
      const matchesFilter = filter === "all" || item.category === filter;
      const haystack = `${item.name} ${item.platform} ${item.type_id} ${item.description}`.toLowerCase();
      return matchesFilter && (!query || haystack.includes(query));
    });
  }

  function renderDetectors() {
    const rows = filteredDetectors();
    $("#detector-count").textContent = state.detectors.length.toLocaleString("pt-BR");
    $("#detector-grid").innerHTML = rows.map((item) => `<article class="detector-card">
      <header><div><h3>${esc(item.name)}</h3><div class="detector-id">${esc(item.type_id)}</div></div>${riskPill(item.risk)}</header>
      <p>${esc(item.description)}</p>
      <div class="detector-meta"><span>PLATAFORMA <strong>${esc(item.platform)}</strong></span><span>CATEGORIA <strong>${esc(item.category)}</strong></span></div>
    </article>`).join("");
    $("#detector-empty").hidden = rows.length > 0;
  }

  function switchView(view) {
    state.activeView = view;
    $$('[data-view-panel]').forEach((panel) => {
      const active = panel.dataset.viewPanel === view;
      panel.hidden = !active;
      panel.classList.toggle("active", active);
    });
    $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
    $(".sidebar").classList.remove("open");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function openModal({ title, kicker = "DETALHES", body, footer = "" }) {
    state.lastFocused = document.activeElement;
    $("#modal-title").textContent = title;
    $("#modal-kicker").textContent = kicker;
    $("#modal-body").innerHTML = body;
    $("#modal-footer").innerHTML = footer;
    $("#modal-backdrop").hidden = false;
    document.body.classList.add("modal-open");
    window.setTimeout(() => $(".close-modal").focus(), 20);
  }

  function closeModal() {
    $("#modal-backdrop").hidden = true;
    document.body.classList.remove("modal-open");
    if (state.lastFocused?.focus) state.lastFocused.focus();
  }

  function detailItem(label, value, full = false, code = false) {
    return `<div class="detail-item ${full ? "full" : ""}"><span>${esc(label)}</span>${code ? `<code>${esc(value ?? "—")}</code>` : `<strong>${esc(value ?? "—")}</strong>`}</div>`;
  }

  async function candidateDetail(id) {
    try {
      const item = await api(`/candidates/${id}`);
      const actions = item.status === "pending_review"
        ? `<button class="button button-danger" data-modal-action="candidate-reject" data-id="${id}">Rejeitar</button><button class="button button-primary" data-modal-action="candidate-authorize" data-id="${id}">Autorizar scan</button>`
        : `<button class="button button-ghost close-modal" type="button">Fechar</button>`;
      openModal({
        title: item.repository,
        kicker: "CANDIDATO GLOBAL",
        body: `<div class="detail-grid">
          ${detailItem("Estado", STATUS_LABELS[item.status] || item.status)}
          ${detailItem("Evento GitHub", item.github_event_id, false, true)}
          ${detailItem("ID do repositório", item.github_repository_id)}
          ${detailItem("Linguagem", item.language || "Não identificada")}
          ${detailItem("Tamanho", formatSize(item.size_kb))}
          ${detailItem("Branch padrão", item.default_branch || "—", false, true)}
          ${detailItem("Criado no GitHub", formatDate(item.repository_created_at))}
          ${detailItem("Evento observado", formatDate(item.event_created_at))}
          ${detailItem("Resultado do filtro", item.filter_reason || "Elegível", true)}
          ${item.authorization_reference ? detailItem("Referência de autorização", item.authorization_reference, true) : ""}
          ${item.authorized_by ? detailItem("Autorizado por", `${item.authorized_by} · ${formatDate(item.authorized_at)}`, true) : ""}
        </div><div class="warning-box">Esta tela contém apenas metadados. Autorizar cria um job de histórico; não autoriza validação ativa, saldo, RPC ou uso de credenciais.</div>`,
        footer: actions,
      });
    } catch (error) { toast("Candidato indisponível", error.message, "error"); }
  }

  function authorizeCandidateModal(id) {
    const item = state.candidates.find((candidate) => Number(candidate.id) === Number(id));
    openModal({
      title: `Autorizar ${item?.repository || `candidato #${id}`}`,
      kicker: "AUTORIZAÇÃO EXPLÍCITA",
      body: `<form class="form-grid" id="authorize-candidate-form">
        <div><label for="authorization-reference">Referência da autorização</label><textarea class="form-textarea" id="authorization-reference" required minlength="8" maxlength="500" placeholder="Ex.: ticket AUTH-1234, autorização do proprietário em 13/08/2026"></textarea><p class="field-hint">Registre uma evidência verificável. Este campo fica no log de auditoria.</p></div>
        <label class="checkbox-row"><input id="authorization-trufflehog" type="checkbox" checked><span>Incluir TruffleHog no scan de histórico, sem verificação externa de credenciais.</span></label>
        <div class="warning-box">Não autorize apenas porque o repositório é público. Use somente escopo próprio, autorização formal ou processo de divulgação defensiva aprovado.</div>
      </form>`,
      footer: `<button class="button button-ghost close-modal" type="button">Cancelar</button><button class="button button-primary" data-modal-action="candidate-authorize-submit" data-id="${id}" type="button">Confirmar e agendar</button>`,
    });
    window.setTimeout(() => $("#authorization-reference").focus(), 30);
  }

  async function authorizeCandidate(id, button) {
    const reference = $("#authorization-reference")?.value.trim();
    if (!reference || reference.length < 8) {
      toast("Referência obrigatória", "Descreva a autorização com pelo menos 8 caracteres.", "error");
      return;
    }
    setBusy(button, true);
    try {
      await api(`/candidates/${id}/authorize-scan`, {
        method: "POST",
        headers: { "X-Actor": "dashboard-admin" },
        body: JSON.stringify({ authorization_reference: reference, trufflehog: $("#authorization-trufflehog")?.checked !== false }),
      });
      closeModal();
      toast("Scan autorizado", "O job de histórico foi criado de forma atômica.");
      await refreshAll(false);
    } catch (error) { toast("Não foi possível autorizar", error.message, "error"); }
    finally { setBusy(button, false); }
  }

  function confirmRejectCandidate(id) {
    const item = state.candidates.find((candidate) => Number(candidate.id) === Number(id));
    openModal({
      title: "Rejeitar candidato?",
      kicker: "DECISÃO DE REVISÃO",
      body: `<p class="confirmation-copy">O repositório <strong>${esc(item?.repository || `#${id}`)}</strong> não será escaneado. A decisão permanece auditável até a retenção configurada.</p>`,
      footer: `<button class="button button-ghost close-modal" type="button">Cancelar</button><button class="button button-danger" data-modal-action="candidate-reject-submit" data-id="${id}" type="button">Rejeitar candidato</button>`,
    });
  }

  async function rejectCandidate(id, button) {
    setBusy(button, true);
    try {
      await api(`/candidates/${id}/reject`, { method: "POST", headers: { "X-Actor": "dashboard-admin" } });
      closeModal();
      toast("Candidato rejeitado", "Nenhum scan foi criado.");
      await refreshAll(false);
    } catch (error) { toast("Não foi possível rejeitar", error.message, "error"); }
    finally { setBusy(button, false); }
  }

  async function findingDetail(id) {
    try {
      const item = await api(`/findings/${id}`);
      const locations = (item.locations || []).map((location) => `<div class="detail-item full"><span>${esc(location.source_kind)} · linha ${Number(location.line_start || 0)}</span><code>${esc(location.path || "(histórico)")}${location.commit_sha ? ` · commit ${esc(truncated(location.commit_sha, 14))}` : ""}</code></div>`).join("");
      openModal({
        title: `${item.platform} em ${item.repository}`,
        kicker: "ACHADO REDIGIDO",
        body: `<div class="detail-grid">
          ${detailItem("Risco", RISK_LABELS[item.risk] || item.risk)}
          ${detailItem("Estado", STATUS_LABELS[item.status] || item.status)}
          ${detailItem("Tipo", item.type_id, false, true)}
          ${detailItem("Hint seguro", item.secret_hint, false, true)}
          ${detailItem("Ambiente", item.environment)}
          ${detailItem("Validação", item.validation_status)}
          ${detailItem("Fingerprint HMAC", item.fingerprint, true, true)}
        </div><div class="detail-section"><h3>Localizações privadas</h3><div class="detail-grid">${locations || detailItem("Localização", "Nenhuma localização", true)}</div></div>
        <div class="warning-box">O valor bruto do segredo não está no PostgreSQL nem nesta resposta da API.</div>`,
        footer: `<button class="button button-ghost close-modal" type="button">Fechar</button>`,
      });
    } catch (error) { toast("Achado indisponível", error.message, "error"); }
  }

  async function notificationDetail(id) {
    try {
      const item = await api(`/notifications/${id}`);
      const findingTags = (item.findings || []).map((finding) => `${riskPill(finding.risk)} <span class="mono">${esc(finding.type_id)}</span>`).join("<br><br>");
      let actions = `<button class="button button-ghost close-modal" type="button">Fechar</button>`;
      if (item.status === "pending_review") actions = `<button class="button button-danger" data-modal-action="notification-reject" data-id="${id}">Rejeitar</button><button class="button button-primary" data-modal-action="notification-approve" data-id="${id}">Aprovar</button>`;
      openModal({
        title: `Alerta para ${item.repository}`,
        kicker: "DRAFT PRIVADO",
        body: `<div class="detail-grid">${detailItem("Estado", STATUS_LABELS[item.status] || item.status)}${detailItem("Canal", item.channel)}${detailItem("Título", item.title, true)}</div>
          <div class="detail-section"><h3>Achados vinculados</h3>${findingTags || "—"}</div>
          <div class="detail-section"><h3>Mensagem privada</h3><pre class="code-block">${esc(item.private_body)}</pre></div>
          <div class="detail-section"><h3>Fallback público sanitizado</h3><pre class="code-block">${esc(item.public_body)}</pre></div>`,
        footer: actions,
      });
    } catch (error) { toast("Draft indisponível", error.message, "error"); }
  }

  async function notificationAction(id, action, button) {
    const labels = { approve: "Notificação aprovada", reject: "Notificação rejeitada", requeue: "Notificação reenfileirada" };
    setBusy(button, true);
    try {
      await api(`/notifications/${id}/${action}`, { method: "POST", headers: { "X-Actor": "dashboard-admin" } });
      closeModal();
      toast(labels[action], action === "approve" ? "O worker de notificação poderá consumir este draft quando estiver ativo." : "Decisão registrada.");
      await refreshAll(false);
    } catch (error) { toast("Ação recusada", error.message, "error"); }
    finally { setBusy(button, false); }
  }

  function jobDetail(id) {
    const item = state.jobs.find((job) => Number(job.id) === Number(id));
    if (!item) return;
    const safe = { ...item };
    openModal({
      title: `Job #${id}`,
      kicker: "UNIDADE DE TRABALHO",
      body: `<div class="detail-grid">${detailItem("Tipo", item.kind, false, true)}${detailItem("Estado", STATUS_LABELS[item.status] || item.status)}${detailItem("Tentativas", `${item.attempts} / ${item.max_attempts}`)}${detailItem("Lease", item.lease_owner || "—", false, true)}${detailItem("Chave idempotente", item.natural_key, true, true)}${item.last_error ? detailItem("Último erro", item.last_error, true) : ""}</div><div class="detail-section"><h3>Payload sem segredo bruto</h3><pre class="code-block">${esc(JSON.stringify(safe.payload, null, 2))}</pre></div>`,
      footer: `<button class="button button-ghost close-modal" type="button">Fechar</button>`,
    });
  }

  function newScanModal() {
    openModal({
      title: "Analisar repositório autorizado",
      kicker: "SCAN MANUAL",
      body: `<form class="form-grid" id="new-scan-form">
        <div><label for="scan-repository">Repositório GitHub</label><input class="form-input" id="scan-repository" required pattern="[^/]+/[^/]+" placeholder="owner/repository" autocomplete="off"><p class="field-hint">Use apenas repositório próprio ou formalmente autorizado.</p></div>
        <label class="checkbox-row"><input id="scan-trufflehog" type="checkbox" checked><span>Executar TruffleHog no histórico além do scanner nativo.</span></label>
        <div class="warning-box">Este botão agenda o scan, mas não liga workers desligados. Acompanhe o job em “Fila de jobs”.</div>
      </form>`,
      footer: `<button class="button button-ghost close-modal" type="button">Cancelar</button><button class="button button-primary" data-modal-action="scan-submit" type="button">Agendar análise</button>`,
    });
    window.setTimeout(() => $("#scan-repository").focus(), 30);
  }

  async function scheduleScan(button) {
    const repository = $("#scan-repository")?.value.trim();
    if (!repository || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
      toast("Repositório inválido", "Use o formato owner/repository.", "error");
      return;
    }
    setBusy(button, true);
    try {
      const result = await api("/jobs/repository", { method: "POST", body: JSON.stringify({ repository, trufflehog: $("#scan-trufflehog")?.checked !== false }) });
      closeModal();
      toast(result.job_created ? "Análise agendada" : "Análise já existente", `Run #${result.run_id}`);
      switchView("jobs");
      await refreshAll(false);
    } catch (error) { toast("Não foi possível agendar", error.message, "error"); }
    finally { setBusy(button, false); }
  }

  function handleTableAction(event) {
    const button = event.target.closest("[data-action]");
    if (!button) return;
    const id = Number(button.dataset.id);
    const action = button.dataset.action;
    if (action === "candidate-detail") candidateDetail(id);
    if (action === "candidate-authorize") authorizeCandidateModal(id);
    if (action === "candidate-reject") confirmRejectCandidate(id);
    if (action === "finding-detail") findingDetail(id);
    if (action === "notification-detail") notificationDetail(id);
    if (action === "notification-approve") notificationAction(id, "approve", button);
    if (action === "notification-reject") notificationAction(id, "reject", button);
    if (action === "notification-requeue") notificationAction(id, "requeue", button);
    if (action === "job-detail") jobDetail(id);
  }

  function handleModalAction(event) {
    const button = event.target.closest("[data-modal-action]");
    if (!button) return;
    const id = Number(button.dataset.id);
    const action = button.dataset.modalAction;
    if (action === "candidate-authorize") authorizeCandidateModal(id);
    if (action === "candidate-authorize-submit") authorizeCandidate(id, button);
    if (action === "candidate-reject") confirmRejectCandidate(id);
    if (action === "candidate-reject-submit") rejectCandidate(id, button);
    if (action === "notification-approve") notificationAction(id, "approve", button);
    if (action === "notification-reject") notificationAction(id, "reject", button);
    if (action === "scan-submit") scheduleScan(button);
  }

  function bindEvents() {
    $("#login-form").addEventListener("submit", (event) => {
      event.preventDefault();
      login($("#admin-token").value, event.submitter);
    });
    $("#toggle-token").addEventListener("click", () => {
      const input = $("#admin-token");
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      $("#toggle-token").setAttribute("aria-label", show ? "Ocultar token" : "Mostrar token");
    });
    $("#logout-button").addEventListener("click", () => logout());
    $("#refresh-button").addEventListener("click", () => refreshAll(true));
    $("#auto-refresh").addEventListener("change", startAutoRefresh);
    $("#new-scan-button").addEventListener("click", newScanModal);
    $("#mobile-menu").addEventListener("click", () => $(".sidebar").classList.toggle("open"));
    $$(".nav-item").forEach((item) => item.addEventListener("click", () => switchView(item.dataset.view)));
    $$('[data-view-jump]').forEach((item) => item.addEventListener("click", () => switchView(item.dataset.viewJump)));
    $$('[data-filter-group]').forEach((group) => group.addEventListener("click", (event) => {
      const button = event.target.closest("button[data-filter]");
      if (!button) return;
      $$('button[data-filter]', group).forEach((item) => item.classList.toggle("active", item === button));
      state.filters[group.dataset.filterGroup] = button.dataset.filter;
      ({ candidates: renderCandidates, findings: renderFindings, notifications: renderNotifications, jobs: renderJobs, detectors: renderDetectors })[group.dataset.filterGroup]?.();
    }));
    $("#candidate-search").addEventListener("input", renderCandidates);
    $("#finding-search").addEventListener("input", renderFindings);
    $("#detector-search").addEventListener("input", renderDetectors);
    $("#main-content").addEventListener("click", handleTableAction);
    $("#modal-backdrop").addEventListener("click", (event) => {
      if (event.target === $("#modal-backdrop") || event.target.closest(".close-modal")) closeModal();
      else handleModalAction(event);
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && !$("#modal-backdrop").hidden) closeModal();
      if (event.key === "Tab" && !$("#modal-backdrop").hidden) {
        const focusable = $$('button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])', $("#modal"));
        if (!focusable.length) return;
        const first = focusable[0], last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    });
  }

  async function bootstrap() {
    bindEvents();
    if (!state.token) {
      showLogin();
      return;
    }
    showApp();
    try {
      await refreshAll(false);
      startAutoRefresh();
    } catch (_) {
      showLogin("Não foi possível restaurar a sessão.");
    }
  }

  bootstrap();
})();
