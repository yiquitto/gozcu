/**
 * GOZCU Dashboard — Real-time SOC Client
 *
 * Handles WebSocket connection, event rendering, decision management,
 * audit trail display, and stats updates.
 */

(function () {
    'use strict';

    // --- State ---
    const state = {
        ws: null,
        events: [],
        decisions: {},
        countdowns: {},
        filters: { source: 'all', risk: 'all' },
        stats: {},
        reconnectAttempts: 0,
        maxReconnect: 10,
    };

    const charts = {
        attackerIp: null,
        threatCategory: null,
        data: {
            ips: {},
            categories: {}
        }
    };

    // --- DOM References ---
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const dom = {
        wsStatus: $('#ws-status'),
        statusDot: $('#ws-status .status-dot'),
        statusText: $('#ws-status .status-text'),
        eventFeed: $('#event-feed'),
        feedEmpty: $('#feed-empty'),
        decisionsContainer: $('#decisions-container'),
        decisionsEmpty: $('#decisions-empty'),
        decisionsCount: $('#decisions-count'),
        auditBody: $('#audit-body'),
        modal: $('#decision-modal'),
        modalBody: $('#modal-body'),
        toastContainer: $('#toast-container'),
        simBadge: $('#sim-mode-badge'),
        filterSource: $('#filter-source'),
        filterRisk: $('#filter-risk'),
    };

    // --- WebSocket ---
    function connectWS() {
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const url = `${protocol}//${location.host}/ws`;

        setWSStatus('connecting', 'Connecting...');

        state.ws = new WebSocket(url);

        state.ws.onopen = () => {
            state.reconnectAttempts = 0;
            setWSStatus('connected', 'Connected');
            showToast('Connected to GOZCU', 'success');
        };

        state.ws.onmessage = (e) => {
            try {
                const msg = JSON.parse(e.data);
                handleMessage(msg);
            } catch (err) {
                console.error('WS parse error:', err);
            }
        };

        state.ws.onclose = () => {
            setWSStatus('disconnected', 'Disconnected');
            scheduleReconnect();
        };

        state.ws.onerror = () => {
            setWSStatus('disconnected', 'Error');
        };
    }

    function scheduleReconnect() {
        if (state.reconnectAttempts >= state.maxReconnect) return;
        state.reconnectAttempts++;
        const delay = Math.min(1000 * Math.pow(2, state.reconnectAttempts), 30000);
        setTimeout(connectWS, delay);
    }

    function setWSStatus(status, text) {
        dom.statusDot.className = `status-dot ${status}`;
        dom.statusText.textContent = text;
    }

    // --- Message Handling ---
    function handleMessage(msg) {
        switch (msg.type) {
            case 'init':
                if (msg.events) {
                    state.events = msg.events;
                    renderAllEvents();
                    // Feed initial events to charts
                    msg.events.reverse().forEach(updateCharts);
                    msg.events.reverse(); // put back in original order
                }
                if (msg.stats) updateStats(msg.stats);
                break;

            case 'new_event':
                state.events.unshift(msg);
                renderEventCard(msg, true);
                updateEventCount();
                updateCharts(msg);
                if (msg.threat_score >= 70) {
                    showToast(`HIGH RISK: ${msg.category} from ${msg.source_ip} (score: ${msg.threat_score})`, 'danger');
                }
                break;

            case 'new_decision':
                addDecision(msg);
                // Automatically switch to decisions tab so the user sees the countdown
                // kullanici paneli aninda gorsun diye karar geldiginde sekmeyi otomatik degistiriyorum.
                const decisionBtn = document.querySelector('.nav-btn[data-tab="decisions"]');
                if (decisionBtn) decisionBtn.click();
                break;

            case 'countdown_tick':
                updateCountdown(msg.decision_id, msg.remaining);
                break;

            case 'decision_update':
                resolveDecision(msg);
                break;

            case 'action_result':
                showToast(
                    `Action ${msg.action}: ${msg.success ? 'Success' : 'Failed'}`,
                    msg.success ? 'success' : 'danger'
                );
                break;
        }

        // Refresh stats periodically
        fetchStats();
    }

    // --- Event Rendering ---
    function renderAllEvents() {
        dom.eventFeed.innerHTML = '';
        if (state.events.length === 0) {
            dom.eventFeed.appendChild(dom.feedEmpty);
            dom.feedEmpty.style.display = '';
            return;
        }
        dom.feedEmpty.style.display = 'none';
        state.events.forEach((ev) => renderEventCard(ev, false));
    }

    function renderEventCard(ev, prepend) {
        if (!passesFilter(ev)) return;

        dom.feedEmpty.style.display = 'none';

        const riskClass = getRiskClass(ev.threat_score);
        const card = document.createElement('div');
        card.className = 'event-card';
        card.dataset.eventId = ev.event_id;

        card.innerHTML = `
            <div class="event-risk-bar ${riskClass}"></div>
            <div class="event-score">
                <div class="score-value" style="color:${getRiskColor(ev.threat_score)}">${ev.threat_score}</div>
                <div class="score-label">${ev.category}</div>
            </div>
            <div class="event-details">
                <div class="event-category">${ev.category}</div>
                <div class="event-reasoning">${escapeHtml(ev.reasoning || '')}</div>
            </div>
            <div class="event-meta">
                <div class="event-ip">${ev.source_ip}</div>
                <div class="event-source-badge source-${ev.source}">${ev.source}</div>
            </div>
        `;

        card.addEventListener('click', () => showEventModal(ev));

        if (prepend) {
            dom.eventFeed.insertBefore(card, dom.eventFeed.firstChild);
        } else {
            dom.eventFeed.appendChild(card);
        }
    }

    function passesFilter(ev) {
        const { source, risk } = state.filters;
        if (source !== 'all' && ev.source !== source) return false;
        if (risk === 'high' && ev.threat_score < 70) return false;
        if (risk === 'medium' && (ev.threat_score < 30 || ev.threat_score >= 70)) return false;
        if (risk === 'low' && ev.threat_score >= 30) return false;
        return true;
    }

    // --- Decision Cards ---
    function addDecision(msg) {
        state.decisions[msg.decision_id] = msg;
        dom.decisionsEmpty.style.display = 'none';
        updateDecisionBadge();

        const card = document.createElement('div');
        card.className = `decision-card ${msg.threat_score >= 90 ? 'urgent' : ''}`;
        card.id = `decision-${msg.decision_id}`;

        const timeout = msg.timeout_seconds || 30;

        card.innerHTML = `
            <div class="decision-header">
                <div class="decision-category" style="color:${getRiskColor(msg.threat_score)}">
                    ${msg.recommended_action || 'ANALYZE'}
                </div>
                <div class="decision-countdown" id="cd-${msg.decision_id}">${timeout}s</div>
            </div>
            <div class="countdown-bar">
                <div class="progress" id="bar-${msg.decision_id}" style="width:100%"></div>
            </div>
            <div class="decision-info">
                <dt>Event ID</dt><dd>${msg.event_id.substring(0, 8)}...</dd>
                <dt>Score</dt><dd>${msg.threat_score}/100</dd>
                <dt>Confidence</dt><dd>${(msg.confidence * 100).toFixed(0)}%</dd>
                <dt>Source IP</dt><dd>${msg.source_ip || 'N/A'}</dd>
            </div>
            <div class="decision-reasoning">${escapeHtml(msg.reasoning || '')}</div>
            <div class="decision-actions">
                <button class="btn btn-success" onclick="window.gozcuApprove('${msg.decision_id}')">
                    Approve
                </button>
                <button class="btn btn-danger" onclick="window.gozcuReject('${msg.decision_id}')">
                    Reject
                </button>
            </div>
        `;

        dom.decisionsContainer.appendChild(card);

        // Store countdown state
        state.countdowns[msg.decision_id] = timeout;
    }

    function updateCountdown(decisionId, remaining) {
        const cdEl = $(`#cd-${decisionId}`);
        const barEl = $(`#bar-${decisionId}`);
        if (cdEl) cdEl.textContent = `${remaining}s`;
        if (barEl) {
            const total = state.countdowns[decisionId] || 30;
            barEl.style.width = `${(remaining / total) * 100}%`;
            if (remaining <= 5) barEl.style.background = 'var(--color-danger)';
        }
    }

    function resolveDecision(msg) {
        const card = $(`#decision-${msg.decision_id}`);
        if (card) {
            card.style.opacity = '0.5';
            card.style.pointerEvents = 'none';
            const cdEl = card.querySelector('.decision-countdown');
            if (cdEl) cdEl.textContent = msg.state;
            const actions = card.querySelector('.decision-actions');
            if (actions) actions.innerHTML = `<span style="color:var(--text-muted);font-size:0.85rem">${msg.state} by ${msg.resolved_by}</span>`;

            setTimeout(() => card.remove(), 3000);
        }
        delete state.decisions[msg.decision_id];
        updateDecisionBadge();

        showToast(`Decision ${msg.state}: ${msg.resolved_by}`, msg.state === 'APPROVED' ? 'success' : 'warning');
    }

    // --- Approve / Reject ---
    window.gozcuApprove = function (decisionId) {
        if (state.ws && state.ws.readyState === WebSocket.OPEN) {
            state.ws.send(JSON.stringify({ type: 'approve', decision_id: decisionId, analyst: 'dashboard_user' }));
        }
    };

    window.gozcuReject = function (decisionId) {
        if (state.ws && state.ws.readyState === WebSocket.OPEN) {
            state.ws.send(JSON.stringify({ type: 'reject', decision_id: decisionId, analyst: 'dashboard_user' }));
        }
    };

    // --- Audit ---
    async function fetchAudit() {
        try {
            const res = await fetch('/api/audit');
            const records = await res.json();
            renderAudit(records);
        } catch (e) {
            console.error('Audit fetch error:', e);
        }
    }

    function renderAudit(records) {
        dom.auditBody.innerHTML = '';
        if (!records.length) {
            dom.auditBody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:40px">No audit records yet</td></tr>';
            return;
        }
        records.reverse().forEach((r) => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${formatTime(r.timestamp)}</td>
                <td style="font-family:var(--font-mono);font-size:0.75rem">${(r.event_id || '').substring(0, 8)}...</td>
                <td>${escapeHtml(r.actor || '')}</td>
                <td><span class="event-source-badge source-${r.action === 'MONITOR' ? 'pre_filter' : 'llm'}">${r.action}</span></td>
                <td style="font-family:var(--font-mono)">${r.threat_score || 0}</td>
                <td>${escapeHtml(r.outcome || '')}</td>
                <td class="hash-cell" title="${r.record_hash || ''}">${(r.record_hash || '').substring(0, 12)}...</td>
            `;
            dom.auditBody.appendChild(tr);
        });
    }

    // --- Stats ---
    async function fetchStats() {
        try {
            const res = await fetch('/api/stats');
            const data = await res.json();
            updateStats(data);
        } catch (e) { /* silent */ }
    }

    function updateStats(data) {
        state.stats = data;
        const pf = data.pipeline?.pre_filter || {};
        const cache = data.pipeline?.cache || {};
        const engine = data.pipeline?.engine || {};

        $('#stat-events-value').textContent = data.events_processed || 0;
        $('#stat-prefiltered-value').textContent = pf.filtered || 0;
        $('#stat-cache-value').textContent = `${cache.hit_rate_percent || 0}%`;
        $('#stat-threats-value').textContent = engine.llm_errors || 0;
        $('#stat-llm-value').textContent = engine.llm_calls || 0;
        $('#stat-audit-value').textContent = data.audit?.total_records || 0;

        if (data.simulation_mode) {
            dom.simBadge.style.display = '';
        } else {
            dom.simBadge.style.display = 'none';
        }
    }

    // --- Modal ---
    function showEventModal(ev) {
        dom.modalBody.innerHTML = `
            <dl class="detail-grid">
                <dt>Event ID</dt><dd>${ev.event_id}</dd>
                <dt>Category</dt><dd style="color:${getRiskColor(ev.threat_score)}">${ev.category}</dd>
                <dt>Score</dt><dd>${ev.threat_score}/100</dd>
                <dt>Confidence</dt><dd>${(ev.confidence * 100).toFixed(1)}%</dd>
                <dt>Source IP</dt><dd>${ev.source_ip}</dd>
                <dt>Source Type</dt><dd>${ev.source_type}</dd>
                <dt>Pipeline</dt><dd>${ev.source}</dd>
                <dt>Timestamp</dt><dd>${formatTime(ev.timestamp)}</dd>
            </dl>
            <div style="margin-top:16px">
                <dt style="color:var(--text-muted);margin-bottom:6px;font-size:0.8rem">AI Reasoning</dt>
                <div class="decision-reasoning">${escapeHtml(ev.reasoning || 'N/A')}</div>
            </div>
        `;
        dom.modal.style.display = '';
    }

    // --- Helpers ---
    function getRiskClass(score) {
        if (score >= 90) return 'risk-critical';
        if (score >= 70) return 'risk-high';
        if (score >= 30) return 'risk-medium';
        if (score > 0) return 'risk-low';
        return 'risk-benign';
    }

    function getRiskColor(score) {
        if (score >= 90) return 'var(--risk-critical)';
        if (score >= 70) return 'var(--risk-high)';
        if (score >= 30) return 'var(--risk-medium)';
        if (score > 0) return 'var(--risk-low)';
        return 'var(--risk-benign)';
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function formatTime(ts) {
        if (!ts) return '-';
        try {
            const d = new Date(ts);
            return d.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch { return ts; }
    }

    function updateDecisionBadge() {
        const count = Object.keys(state.decisions).length;
        dom.decisionsCount.style.display = count > 0 ? '' : 'none';
        dom.decisionsCount.textContent = count;
    }

    function updateEventCount() {
        const threats = state.events.filter((e) => e.threat_score >= 70).length;
        $('#stat-threats-value').textContent = threats;
    }

    function showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        dom.toastContainer.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(20px)';
            toast.style.transition = '0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    // --- Tab Navigation ---
    $$('.nav-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            $$('.nav-btn').forEach((b) => b.classList.remove('active'));
            btn.classList.add('active');
            $$('.tab-content').forEach((t) => t.classList.remove('active'));
            $(`#tab-${btn.dataset.tab}`).classList.add('active');

            if (btn.dataset.tab === 'audit') fetchAudit();
        });
    });

    // --- Filters ---
    dom.filterSource.addEventListener('change', (e) => {
        state.filters.source = e.target.value;
        renderAllEvents();
    });

    dom.filterRisk.addEventListener('change', (e) => {
        state.filters.risk = e.target.value;
        renderAllEvents();
    });

    $('#btn-clear-feed').addEventListener('click', () => {
        state.events = [];
        renderAllEvents();
    });

    $('#btn-refresh-audit').addEventListener('click', fetchAudit);

    // Modal close
    $('#modal-close').addEventListener('click', () => dom.modal.style.display = 'none');
    $('.modal-overlay').addEventListener('click', () => dom.modal.style.display = 'none');

    // --- Charts ---
    function initCharts() {
        // canli istatistikleri chart.js kullanarak cizdirdigim yer.
        const ctxIp = document.getElementById('attackerIpChart');
        const ctxCat = document.getElementById('threatCategoryChart');
        if (!ctxIp || !ctxCat) return;

        Chart.defaults.color = '#94a3b8';
        Chart.defaults.font.family = "'Inter', -apple-system, sans-serif";

        charts.attackerIp = new Chart(ctxIp.getContext('2d'), {
            type: 'bar',
            data: { labels: [], datasets: [{ label: 'Attacks', data: [], backgroundColor: 'rgba(59, 130, 246, 0.4)', borderColor: '#3b82f6', borderWidth: 1, borderRadius: 4 }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: 'rgba(255,255,255,0.03)' } }, x: { grid: { display: false } } } }
        });

        charts.threatCategory = new Chart(ctxCat.getContext('2d'), {
            type: 'doughnut',
            data: { labels: [], datasets: [{ data: [], backgroundColor: ['#e11d48', '#ea580c', '#d97706', '#3b82f6', '#059669', '#64748b'], borderWidth: 0 }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { boxWidth: 12 } } }, cutout: '70%' }
        });
    }

    function updateCharts(ev) {
        if (ev.source === 'pre_filter' || ev.category === 'BENIGN') return; // Focus charts on actual threats
        
        // yeni bir zararli bulundugunda sayfalari yenilemeye gerek kalmadan grafikleri anlik guncelliyorum.
        // IP Data
        const ip = ev.source_ip || 'Unknown';
        charts.data.ips[ip] = (charts.data.ips[ip] || 0) + 1;
        
        // Category Data
        const cat = ev.category || 'UNKNOWN';
        charts.data.categories[cat] = (charts.data.categories[cat] || 0) + 1;

        if (!charts.attackerIp || !charts.threatCategory) return;

        // Update IP Chart (Top 5)
        const sortedIps = Object.entries(charts.data.ips).sort((a, b) => b[1] - a[1]).slice(0, 5);
        charts.attackerIp.data.labels = sortedIps.map(i => i[0]);
        charts.attackerIp.data.datasets[0].data = sortedIps.map(i => i[1]);
        charts.attackerIp.update();

        // Update Category Chart
        charts.threatCategory.data.labels = Object.keys(charts.data.categories);
        charts.threatCategory.data.datasets[0].data = Object.values(charts.data.categories);
        charts.threatCategory.update();
    }

    // --- Init ---
    initCharts();
    connectWS();
    fetchStats();
    setInterval(fetchStats, 5000);

})();
