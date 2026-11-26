/* Interactive visuals for radar-decipher.html. Needs charts.js (window.IdpsCharts) loaded first.
   Scenario weights, tiers, mitigations, detectors and DECIPHER endpoints come from
   window.RADAR_CONFIG (assets/radar-config.js, same data as radar-config.json), generated from
   RADAR's own files by docs/website/tools/build_radar_config.py.
   The only fixed values here are the worked example's inputs (EXAMPLE below).
   Styles: assets/radar-decipher.css. Used by radar-decipher.html and product-presentation.html. */
(function () {
  "use strict";

  var C = window.IdpsCharts;
  if (!C) return;
  var svgEl = C.svgEl, htmlEl = C.htmlEl, fmt = C.fmt, bindTip = C.bindTip;

  var CONFIG_URL = "assets/radar-config.json";

  // Worked example: a failed-login burst (rule 210013) for a model-mode user, an off-hours
  // anomaly from the per-user RCF detector (grade 0.8, confidence 0.9) and a CTI score of 0.56.
  var EXAMPLE = { scenario: "suspicious_login", rule: "210013", user: "trent", host: "srv-01", ip: "203.0.113.45",
    adRule: "210040", grade: 0.8, conf: 0.9, T: 0.56 };

  var TERM = {
    A: { name: "Anomaly A", color: "var(--viz-3)" },
    S: { name: "Signature S", color: "var(--viz-2)" },
    T: { name: "CTI T", color: "var(--viz-1)" }
  };

  var TYPE_LABEL = { signature: "Signature", anomaly: "Anomaly (RCF)", hybrid: "Hybrid (fusion)" };

  var CFG = null;

  /* ── Helpers over the generated config ── */
  function sc(name) { return CFG.scenarios[name]; }
  function names() { return Object.keys(CFG.scenarios); }
  function n2(v) { return String(Math.round(v * 1000) / 1000); }
  function priority(tier) { return CFG.decipher.tier_priority[String(tier)] || ""; }

  // Same rule as RiskEngine.compute: R < tier1_min → 0, < tier1_max → 1, < tier2_max → 2, else 3
  function tierOf(r, b) {
    if (r < b[0]) return 0;
    if (r < b[1]) return 1;
    if (r < b[2]) return 2;
    return 3;
  }

  function planned(s, tier) {
    return tier === 3 ? s.mitigations.tier3 : tier === 2 ? s.mitigations.tier2 : [];
  }

  function likelihoodOf(s, ruleId) {
    for (var i = 0; i < s.signature_likelihood.length; i++) {
      var e = s.signature_likelihood[i];
      if ((e.rule_ids || []).indexOf(ruleId) >= 0) return e.weight;
    }
    return 0;
  }

  function decipherStatus(name) {
    var s = sc(name);
    if (s.decipher_endpoint) return "wired";
    return s.weights.T > 0 ? "possible" : "not used";
  }

  function wired() {
    return names().filter(function (n) { return sc(n).decipher_endpoint; });
  }

  // The worked example, computed from the config
  function example(down) {
    var s = sc(EXAMPLE.scenario);
    var L = likelihoodOf(s, EXAMPLE.rule);
    var S = L * s.signature_impact;
    var A = EXAMPLE.grade * EXAMPLE.conf;
    var T = down ? 0 : EXAMPLE.T;
    var r = s.weights.S * S + s.weights.A * A + s.weights.T * T;
    var tier = tierOf(r, s.tiers);
    return { s: s, L: L, S: S, A: A, T: T, r: r, tier: tier, planned: planned(s, tier) };
  }

  function bands(b) {
    var out = [];
    if (b[0] > 0) out.push({ name: "T0", from: 0, to: b[0], fill: "var(--viz-t0)" });
    out.push({ name: "T1", from: b[0], to: b[1], fill: "var(--viz-t1)" });
    out.push({ name: "T2", from: b[1], to: b[2], fill: "var(--viz-t2)" });
    out.push({ name: "T3", from: b[2], to: 1, fill: "var(--viz-t3)" });
    return out;
  }

  function code(parent, text) { return htmlEl("code", {}, parent, text); }

  /* ── Risk meter: weighted terms stacked over the tier ladder ── */
  function drawMeter(host, label) {
    var W = 600, H = 132, left = 14, right = 14, barY = 30, barH = 22, bandY = 66, bandH = 26;
    var plotW = W - left - right;
    var x = function (v) { return left + Math.max(0, Math.min(1, v)) * plotW; };

    var scroll = htmlEl("div", { class: "viz-scroll" }, host);
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": label }, scroll);
    var bandG = svgEl("g", {}, svg);
    var segG = svgEl("g", {}, svg);
    svgEl("rect", { x: left, y: barY, width: plotW, height: barH, fill: "none", stroke: "var(--viz-axis)", rx: 3 }, svg);
    var marker = svgEl("line", { y1: barY - 8, y2: bandY + bandH + 4, stroke: "var(--ink, #17212f)", "stroke-width": 2 }, svg);
    var readout = svgEl("text", { y: barY - 12, class: "t-strong", "text-anchor": "middle" }, svg);
    [0, 0.25, 0.5, 0.75, 1].forEach(function (v) {
      svgEl("text", { x: x(v), y: H - 8, "text-anchor": v === 0 ? "start" : v === 1 ? "end" : "middle", class: "t-small" }, svg, String(v));
    });

    return function update(tiers, parts, shown) {
      bandG.textContent = "";
      bands(tiers).forEach(function (t, i) {
        svgEl("rect", { x: x(t.from) + (i ? 1 : 0), y: bandY, width: Math.max(0, x(t.to) - x(t.from) - (i ? 1 : 0)), height: bandH, fill: t.fill }, bandG);
        if (x(t.to) - x(t.from) > 26) svgEl("text", { x: x(t.from) + 6, y: bandY + 17, class: "t-strong t-small" }, bandG, t.name);
      });
      segG.textContent = "";
      var acc = 0;
      parts.forEach(function (p) {
        if (p.value <= 0) return;
        var seg = svgEl("rect", { x: x(acc), y: barY, width: Math.max(1, x(acc + p.value) - x(acc)), height: barH, class: "hit" }, segG);
        seg.style.fill = p.color;
        bindTip(seg, [p.name + ": " + fmt(p.value), p.detail]);
        acc += p.value;
      });
      var r = Math.min(1, acc);
      marker.setAttribute("x1", x(r));
      marker.setAttribute("x2", x(r));
      readout.setAttribute("x", Math.min(W - 70, Math.max(70, x(r))));
      var vis = shown === false ? "hidden" : "visible";
      marker.setAttribute("visibility", vis);
      readout.setAttribute("visibility", vis);
      readout.textContent = "R = " + r.toFixed(3) + " → T" + tierOf(r, tiers);
      return r;
    };
  }

  /* ── Architecture: who talks to whom ── */
  function drawArch(host) {
    var W = 900, H = 424;
    var scroll = htmlEl("div", { class: "viz-scroll" }, host);
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, role: "group", "aria-label": "IDPS-ESCAPE components and the data passed between them" }, scroll);
    var defs = svgEl("defs", {}, svg);
    var mk = svgEl("marker", { id: "rd-arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, defs);
    svgEl("path", { d: "M0,0 L10,5 L0,10 z", fill: "var(--muted, #3d6363)" }, mk);

    var rcf = [];
    names().forEach(function (n) {
      sc(n).anomaly_sources.forEach(function (a) { if (a.kind === "rcf") rcf.push(a.name + " (per " + a.entity + ")"); });
    });

    var N = {
      sonar: { x: 16, y: 26, w: 160, h: 58, t: "SONAR", s: "separate, optional", muted: true,
        tip: ["SONAR (separate process)", "Multivariate anomaly detection. It can push anomaly events to Wazuh,", "but a finalized RADAR–SONAR integration is not available yet: no RADAR scenario uses it today."] },
      agents: { x: 16, y: 176, w: 160, h: 64, t: "Wazuh agents", s: "endpoints, logs",
        tip: ["Wazuh agents", "Ship logs and metrics from endpoints, and run the active-response scripts RADAR triggers."] },
      manager: { x: 236, y: 40, w: 200, h: 70, t: "Wazuh manager", s: "decoders + signature rules",
        tip: ["Wazuh manager", "RADAR's decoders and signature rules (for example 210013, failed-login burst).", "Anomaly alerts arrive here too, through the webhook, and are matched by their own rules.", "Every scenario rule triggers the same active response, radar_ar.py."] },
      detectors: { x: 236, y: 262, w: 200, h: 76, t: "RADAR anomaly detectors", s: "OpenSearch AD (RCF)", main: true,
        tip: ["RADAR anomaly detectors"].concat(rcf.length ? rcf : ["none configured"]).concat(["Defined in radar/config.yaml and created by run-radar.sh, each with an alerting monitor and webhook."]) },
      radar: { x: 492, y: 150, w: 180, h: 76, t: "RADAR", s: "risk score + response", main: true,
        tip: ["RADAR risk engine (radar_ar.py)", "Scores R = wA·A + wS·S + wT·T per scenario, fuses a signature alert with a recent anomaly on the same user or host, picks a tier and acts."] },
      decipher: { x: 744, y: 156, w: 150, h: 64, t: "DECIPHER", s: "SATRAP-DL, CTI", main: true,
        tip: ["DECIPHER (SATRAP-DL)", "Turns the alert's indicators into a CTI score T using MISP events.", "Opens incident cases in Flowintel."] },
      misp: { x: 744, y: 30, w: 150, h: 54, t: "MISP", s: "threat intelligence",
        tip: ["MISP", "Events and attributes: threat level, tags, admiralty ratings, sightings, analysis state."] },
      flowintel: { x: 744, y: 296, w: 150, h: 54, t: "Flowintel", s: "incident cases",
        tip: ["Flowintel", "One case per decision at tier 1 or above, with score breakdown, IOCs and MISP context."] },
      email: { x: 492, y: 300, w: 180, h: 48, t: "Analyst email", s: "",
        tip: ["Email", "Score breakdown, IOCs, actions taken or withheld, and the case link."] }
    };

    function edge(d, label, lx, ly, opts) {
      opts = opts || {};
      svgEl("path", { d: d, fill: "none", stroke: "var(--muted, #3d6363)", "stroke-width": 1.4, "marker-end": "url(#rd-arrow)",
        "stroke-dasharray": opts.dashed ? "5 4" : "none", opacity: opts.muted ? 0.55 : 1 }, svg);
      if (label) svgEl("text", { x: lx, y: ly, "text-anchor": opts.anchor || "middle", class: "t-small" }, svg, label);
    }
    edge("M176,55 L236,62", "can push events", 182, 30, { dashed: true, muted: true, anchor: "start" });
    edge("M150,176 L250,110", "logs", 186, 140, { anchor: "end" });
    edge("M290,110 L290,262", "events", 282, 190, { anchor: "end" });
    edge("M382,262 L382,110", "anomaly alerts", 390, 182, { anchor: "start" });
    svgEl("text", { x: 390, y: 198, class: "t-small" }, svg, "via webhook");
    edge("M436,92 L492,168", "scenario alerts", 474, 112, { anchor: "start" });
    edge("M672,176 L744,176", "analyze", 708, 168);
    edge("M744,198 L672,198", "T + events", 708, 216);
    edge("M819,156 L819,84", "IOC lookup", 827, 124, { anchor: "start" });
    edge("M819,220 L819,296", "case", 827, 262, { anchor: "start" });
    edge("M582,226 L582,300", "notify", 590, 266, { anchor: "start" });
    edge("M492,214 L466,214 L466,404 L96,404 L96,240", "active response (tier 2–3, opt-in)", 280, 396, { dashed: true });

    Object.keys(N).forEach(function (k) {
      var n = N[k];
      var g = svgEl("g", { opacity: n.muted ? 0.7 : 1 }, svg);
      svgEl("rect", { x: n.x, y: n.y, width: n.w, height: n.h, rx: 12,
        fill: n.main ? "var(--surface-alt, #f0fafa)" : "var(--surface, #fff)",
        stroke: n.main ? "var(--brand, #0d8b94)" : "var(--viz-axis)", "stroke-width": n.main ? 2 : 1.2,
        "stroke-dasharray": n.muted ? "5 4" : "none" }, g);
      svgEl("text", { x: n.x + n.w / 2, y: n.y + (n.s ? n.h / 2 - 3 : n.h / 2 + 5), "text-anchor": "middle", class: "t-strong" }, g, n.t);
      if (n.s) svgEl("text", { x: n.x + n.w / 2, y: n.y + n.h / 2 + 15, "text-anchor": "middle", class: "t-small" }, g, n.s);
      bindTip(svgEl("rect", { class: "hit", x: n.x, y: n.y, width: n.w, height: n.h, rx: 12 }, g), n.tip);
    });
  }

  /* ── Scenario families: signature, anomaly, hybrid ── */
  function drawScenarioTypes(host) {
    var grid = htmlEl("div", { class: "types" }, host);
    ["signature", "anomaly", "hybrid"].forEach(function (type) {
      var col = htmlEl("div", { class: "types-col types-" + type }, grid);
      htmlEl("div", { class: "types-title" }, col, TYPE_LABEL[type]);
      var list = names().filter(function (n) { return sc(n).type === type; });
      list.forEach(function (n) {
        var s = sc(n);
        var lines = [n, "Weights: A " + s.weights.A + " · S " + s.weights.S + " · T " + s.weights.T];
        s.anomaly_sources.forEach(function (a) {
          lines.push((a.kind === "rcf" ? "RCF detector " : "Query monitor, ") + a.name + ", per " + a.entity);
        });
        if (s.fusion) lines.push("Fusion window " + s.fusion.window_minutes + " min, lead " + s.fusion.ad_lead_minutes + " min");
        if (s.decipher_endpoint) lines.push("DECIPHER: " + s.decipher_endpoint);
        var chip = htmlEl("span", { class: "chip-btn types-chip" }, col, n);
        bindTip(chip, lines);
        chip.setAttribute("role", "button");
      });
      if (!list.length) htmlEl("span", { class: "types-empty" }, col, "none");
    });
  }

  /* ── Detectors defined in code (technical) ── */
  function drawDetectors(host) {
    var wrap = htmlEl("div", { class: "table-wrap" }, host);
    var table = htmlEl("table", {}, wrap);
    var tr = htmlEl("tr", {}, htmlEl("thead", {}, table));
    ["Scenario", "Detector", "Kind", "Per", "Features", "Interval"].forEach(function (h) { htmlEl("th", {}, tr, h); });
    var tb = htmlEl("tbody", {}, table);
    names().forEach(function (n) {
      sc(n).anomaly_sources.forEach(function (a) {
        var row = htmlEl("tr", {}, tb);
        code(htmlEl("td", {}, row), n);
        code(htmlEl("td", {}, row), a.name);
        htmlEl("td", {}, row, a.kind === "rcf" ? "RCF" : "query monitor");
        code(htmlEl("td", {}, row), a.entity);
        htmlEl("td", {}, row, (a.features || []).join(", ") || "—");
        htmlEl("td", { class: "num" }, row, a.interval_minutes ? a.interval_minutes + " min" : "—");
      });
    });
  }

  /* ── One alert, end to end ── */
  var STEPS = [
    { phase: "Monitor", label: "Detect", view: function () { return {
      title: "Wazuh raises a signature alert",
      body: "Rule " + EXAMPLE.rule + " sees five failed logins for " + EXAMPLE.user + " on " + EXAMPLE.host + " within 60 seconds.",
      code: "rule " + EXAMPLE.rule + " · RADAR SuspiciousLogin: failed-burst (≥5 in 60s)" }; } },
    { phase: "Analyze", label: "Match", view: function (e) { return {
      title: "RADAR matches it to a scenario",
      body: "Rule " + EXAMPLE.rule + " is a signature rule of " + EXAMPLE.scenario + ", a hybrid scenario. Its signature risk is likelihood × impact, both set in ar.yaml.",
      code: "S = likelihood " + n2(e.L) + " × impact " + n2(e.s.signature_impact) + " = " + n2(e.S) }; } },
    { phase: "Analyze", label: "Context", view: function () { return {
      title: "RADAR gathers context",
      body: "It collects the events around the alert: source IPs, users and hosts. Context goes to DECIPHER, the case and the email. It never changes the score.",
      code: "src_ips: [" + EXAMPLE.ip + "] · user: " + EXAMPLE.user + " · host: " + EXAMPLE.host }; } },
    { phase: "Analyze", label: "Ask DECIPHER", view: function (e, st) { return st.down ? {
      title: "DECIPHER is unreachable",
      body: "The health check fails, so RADAR skips enrichment and carries on with T = 0. Nothing waits for DECIPHER.",
      code: "GET " + CFG.decipher.health + " → no answer · T = 0", warn: true } : {
      title: "DECIPHER checks the indicators against MISP",
      body: "RADAR sends the user, host and source IPs. DECIPHER looks them up in MISP and returns a CTI score with the matching events.",
      code: "POST " + e.s.decipher_endpoint + " → severity " + n2(EXAMPLE.T) }; } },
    { phase: "Analyze", label: "Fuse", view: function (e) { return {
      title: "An RCF anomaly fills the missing term",
      body: "A signature alert carries no anomaly term of its own. RADAR looks back for an anomaly alert on " + EXAMPLE.user +
        ": the per-user RCF detector had flagged unusual off-hours activity (rule " + EXAMPLE.adRule + "). The burst falls inside that anomaly's data window, so it counts in full.",
      code: "A = grade " + EXAMPLE.grade + " × confidence " + EXAMPLE.conf + " × weight 1 = " + n2(e.A) }; } },
    { phase: "Analyze", label: "Score", view: function (e, st) { return {
      title: "Weighted sum, then a tier",
      body: EXAMPLE.scenario + " weighs signature " + e.s.weights.S + ", anomaly " + e.s.weights.A + " and CTI " + e.s.weights.T +
        ". Its tiers start at " + e.s.tiers.join(", ") + "." +
        (st.down ? " Without CTI the score lands in tier " + e.tier + "." : " With CTI it lands in tier " + e.tier + "."),
      code: "R = " + e.s.weights.S + " × " + n2(e.S) + " + " + e.s.weights.A + " × " + n2(e.A) + " + " + e.s.weights.T + " × " + fmt(e.T) + " = " + e.r.toFixed(3) + " → T" + e.tier }; } },
    { phase: "Knowledge", label: "Open case", view: function (e, st) { return st.down ? {
      title: "No case this time",
      body: "Cases are opened through DECIPHER, so none is created while it is down. The email still carries the full breakdown.",
      code: "case: none", warn: true } : e.tier < 1 ? {
      title: "No case at tier 0",
      body: "The score is below the first tier line, so RADAR only logs the decision.",
      code: "case: none" } : {
      title: "DECIPHER opens a Flowintel case",
      body: "The case records the score breakdown, MISP events, IOCs and a decision ID. Its priority follows the tier.",
      code: "POST " + CFG.decipher.incident + " · " + priority(e.tier) }; } },
    { phase: "Plan", label: "Plan", view: function (e, st) {
      if (!e.planned.length) return { title: "No mitigation at this tier", body: "Tier " + e.tier + " of " + EXAMPLE.scenario + " lists no mitigation.", code: "mitigations: []" };
      return st.mitOff ? {
        title: "Actions are planned, then withheld",
        body: "Tier " + e.tier + " calls for " + e.planned.join(" and ") + ", but this run has allow_mitigation: false. RADAR logs what it would have done and why.",
        code: "mitigations: [] · would_be: [" + e.planned.join(", ") + "] · withheld_reason: mitigation_disabled", warn: true } : {
        title: "The tier picks the actions",
        body: "Tier " + e.tier + " of " + EXAMPLE.scenario + " runs " + e.planned.join(" and ") + ". Targets come from the triggering alert only.",
        code: "mitigations_tier" + e.tier + ": [" + e.planned.join(", ") + "]" }; } },
    { phase: "Execute", label: "Act + notify", view: function (e, st) {
      var acts = st.mitOff ? [] : e.planned;
      var did = acts.map(function (m) {
        return m === "firewall-drop" ? EXAMPLE.ip + " is dropped at the firewall" : m === "lock_user_linux.sh" ? EXAMPLE.user + "'s account is locked on " + EXAMPLE.host : m + " runs";
      });
      return {
        title: acts.length ? "Contain, then tell the analyst" : "Nothing is blocked. The analyst is told.",
        body: (acts.length ? did.join(", and ") + ". " : "No command runs. ") +
          "The email lists the score breakdown, IOCs, actions taken or withheld" + (st.down ? "." : ", and the case link."),
        code: (acts.length ? acts.map(function (m) { return m === "firewall-drop" ? m + " " + EXAMPLE.ip : m === "lock_user_linux.sh" ? m + " " + EXAMPLE.user : m; }).join(" · ") : "no active response") + " · email sent" }; } }
  ];

  function drawJourney(host) {
    var st = { step: 0, down: false, mitOff: false };
    var timer = null;

    var controls = htmlEl("div", { class: "j-controls" }, host);
    var back = htmlEl("button", { type: "button", class: "j-btn" }, controls, "← Back");
    var next = htmlEl("button", { type: "button", class: "j-btn j-btn-primary" }, controls, "Next →");
    var play = htmlEl("button", { type: "button", class: "j-btn" }, controls, "▶ Play");
    var tg = htmlEl("div", { class: "j-toggles" }, controls);
    function toggle(text, key) {
      var lab = htmlEl("label", { class: "switch" }, tg);
      var input = htmlEl("input", { type: "checkbox" }, lab);
      htmlEl("span", {}, lab, text);
      input.addEventListener("change", function () { st[key] = input.checked; render(); });
    }
    toggle("DECIPHER unreachable", "down");
    toggle("allow_mitigation: false", "mitOff");

    var rail = htmlEl("ol", { class: "j-rail" }, host);
    var railButtons = STEPS.map(function (step, i) {
      var b = htmlEl("button", { type: "button", "data-phase": step.phase }, htmlEl("li", {}, rail));
      htmlEl("span", { class: "j-num" }, b, String(i + 1));
      htmlEl("span", { class: "j-label" }, b, step.label);
      htmlEl("span", { class: "j-phase" }, b, step.phase);
      b.addEventListener("click", function () { stop(); st.step = i; render(); });
      return b;
    });

    var body = htmlEl("div", { class: "j-body" }, host);
    var card = htmlEl("div", { class: "j-card", "aria-live": "polite" }, body);
    var cPhase = htmlEl("div", { class: "j-card-phase" }, card);
    var cTitle = htmlEl("h3", {}, card);
    var cText = htmlEl("p", {}, card);
    var cCode = htmlEl("code", { class: "j-code" }, card);

    var side = htmlEl("div", { class: "j-side" }, body);
    htmlEl("div", { class: "j-side-title" }, side, "Risk score so far");
    var meter = drawMeter(htmlEl("div", { class: "viz viz-flat" }, side), "Risk score built up from the terms known at this step");
    var outcome = htmlEl("dl", { class: "j-outcome" }, side);

    function row(k, v, cls) {
      htmlEl("dt", {}, outcome, k);
      htmlEl("dd", { class: cls || "" }, outcome, v);
    }

    function render() {
      var e = example(st.down);
      var v = STEPS[st.step].view(e, st);
      railButtons.forEach(function (b, i) {
        b.classList.toggle("is-current", i === st.step);
        b.classList.toggle("is-done", i < st.step);
        b.setAttribute("aria-current", i === st.step ? "step" : "false");
      });
      cPhase.textContent = "Step " + (st.step + 1) + " of " + STEPS.length + " · " + STEPS[st.step].phase;
      cTitle.textContent = v.title;
      cText.textContent = v.body;
      cCode.textContent = v.code;
      card.classList.toggle("is-warn", !!v.warn);
      back.disabled = st.step === 0;
      next.disabled = st.step === STEPS.length - 1;

      var w = e.s.weights, parts = [];
      if (st.step >= 1) parts.push({ name: TERM.S.name, color: TERM.S.color, value: w.S * e.S, detail: w.S + " × S " + n2(e.S) });
      if (st.step >= 3) parts.push({ name: TERM.T.name, color: TERM.T.color, value: w.T * e.T, detail: st.down ? "DECIPHER down: T = 0" : w.T + " × T " + n2(e.T) });
      if (st.step >= 4) parts.push({ name: TERM.A.name, color: TERM.A.color, value: w.A * e.A, detail: w.A + " × A " + n2(e.A) + " (fused RCF anomaly)" });
      meter(e.s.tiers, parts, st.step >= 5);

      outcome.textContent = "";
      var pending = "…";
      var noCase = st.down || e.tier < 1;
      row("Tier", st.step >= 5 ? "T" + e.tier : pending);
      row("Flowintel case", st.step >= 6 ? (noCase ? "not created" : "opened, " + priority(e.tier)) : pending, st.step >= 6 && st.down ? "is-warn" : "");
      row("Mitigation", st.step >= 7 ? (!e.planned.length ? "none at this tier" : st.mitOff ? "withheld (mitigation_disabled)" : e.planned.join(" + ")) : pending, st.step >= 7 && st.mitOff && e.planned.length ? "is-warn" : "");
      row("Email", st.step >= 8 ? (e.tier < 1 ? "not sent (tier 0)" : noCase ? "sent, no case link" : "sent with case link") : pending);
    }

    function stop() {
      if (timer) { clearInterval(timer); timer = null; play.textContent = "▶ Play"; }
    }
    back.addEventListener("click", function () { stop(); st.step = Math.max(0, st.step - 1); render(); });
    next.addEventListener("click", function () { stop(); st.step = Math.min(STEPS.length - 1, st.step + 1); render(); });
    play.addEventListener("click", function () {
      if (timer) { stop(); return; }
      if (st.step === STEPS.length - 1) st.step = 0;
      play.textContent = "❚❚ Pause";
      render();
      timer = setInterval(function () {
        if (st.step >= STEPS.length - 1) { stop(); return; }
        st.step += 1;
        render();
      }, 2600);
    });
    render();
  }

  /* ── Risk playground: any scenario, any A, S, T ── */
  function drawPlayground(host) {
    var form = htmlEl("div", { class: "pg-form" }, host);
    var selLab = htmlEl("label", { class: "pg-select" }, form);
    htmlEl("span", {}, selLab, "Scenario");
    var sel = htmlEl("select", {}, selLab);
    names().forEach(function (n) { htmlEl("option", { value: n }, sel, n + " · " + TYPE_LABEL[sc(n).type].toLowerCase()); });
    sel.value = EXAMPLE.scenario;

    var e0 = example(false);
    var vals = { A: e0.A, S: e0.S, T: EXAMPLE.T };
    var sliders = {};
    ["S", "A", "T"].forEach(function (k) {
      var wrap = htmlEl("label", { class: "pg-slider" }, form);
      var head = htmlEl("span", { class: "pg-slider-head" }, wrap);
      htmlEl("i", { style: "background:" + TERM[k].color }, head);
      htmlEl("span", {}, head, TERM[k].name);
      var out = htmlEl("b", {}, head);
      var input = htmlEl("input", { type: "range", min: 0, max: 1, step: 0.01, value: vals[k] }, wrap);
      var note = htmlEl("small", {}, wrap);
      input.addEventListener("input", function () { vals[k] = parseFloat(input.value); render(); });
      sliders[k] = { input: input, out: out, note: note };
    });

    var meter = drawMeter(htmlEl("div", { class: "viz viz-flat" }, host), "Risk score for the chosen scenario and term values");
    var formula = htmlEl("p", { class: "pg-formula" }, host);
    var result = htmlEl("dl", { class: "j-outcome pg-outcome" }, host);

    function render() {
      var s = sc(sel.value);
      var parts = [];
      ["S", "A", "T"].forEach(function (k) {
        var o = sliders[k], w = s.weights[k];
        o.out.textContent = fmt(vals[k]) + "  × " + w;
        o.input.disabled = w === 0;
        o.note.textContent = w === 0 ? "Weight 0 in this scenario." :
          k === "T" && !s.decipher_endpoint ? "No DECIPHER analyze call is wired for this scenario yet, so T is 0 today." :
          k === "A" && s.type === "hybrid" ? "Comes from a fused anomaly alert on the same user or host." : "";
        if (w > 0) parts.push({ name: TERM[k].name, color: TERM[k].color, value: w * vals[k], detail: w + " × " + fmt(vals[k]) });
      });
      var r = meter(s.tiers, parts, true);
      var tier = tierOf(r, s.tiers);
      formula.textContent = "R = " + ["S", "A", "T"].filter(function (k) { return s.weights[k] > 0; })
        .map(function (k) { return s.weights[k] + " × " + fmt(vals[k]); }).join(" + ") + " = " + r.toFixed(3) +
        " · tier lines " + s.tiers.join(", ");
      var p = planned(s, tier);
      result.textContent = "";
      function row(k, v, cls) { htmlEl("dt", {}, result, k); htmlEl("dd", { class: cls || "" }, result, v); }
      row("Tier", "T" + tier);
      row("Email + Flowintel case", tier >= 1 ? "yes, " + priority(tier) : "no, logged only");
      row("Planned mitigation", p.length ? p.join(" + ") : "none at this tier");
      row("allow_mitigation (shipped)", s.allow_mitigation ? "true, runs" : "false, withheld and logged", s.allow_mitigation ? "" : "is-warn");
    }
    sel.addEventListener("change", render);
    render();
  }

  /* ── CTI: what drives T, and what T does to the example scenario ── */
  var CTI_FACTORS = [
    { group: "Severity", name: "Threat level", values: "Low · medium · high · undefined",
      text: "The threat level the MISP event was published with." },
    { group: "Severity", name: "Threat-related tags", values: "mitre-attack-pattern · mitre-intrusion-set · …",
      text: "ATT&CK tags tie the event to known techniques and actors." },
    { group: "Confidence", name: "Admiralty tags", values: "Information credibility · source reliability",
      text: "How credible the information is and how reliable its source has been." },
    { group: "Confidence", name: "Sightings", values: "Reported observations of the indicator",
      text: "Other parties seeing the same indicator raise confidence that it is live." },
    { group: "Confidence", name: "Analysis state", values: "Initial · ongoing · completed",
      text: "A completed analysis is trusted more than an initial one." }
  ];

  function drawCtiFactors(host) {
    var grid = htmlEl("div", { class: "cti-grid" }, host);
    var src = htmlEl("div", { class: "cti-src" }, grid);
    htmlEl("b", {}, src, "MISP events");
    htmlEl("span", {}, src, "that match the alert's indicators, using event and attribute data per event");
    var groups = htmlEl("div", { class: "cti-groups" }, grid);
    var buttons = [];
    ["Severity", "Confidence"].forEach(function (g) {
      var box = htmlEl("div", { class: "cti-group" }, groups);
      htmlEl("div", { class: "cti-group-title" }, box, g === "Severity" ? "Severity: how bad" : "Confidence: how sure");
      CTI_FACTORS.filter(function (f) { return f.group === g; }).forEach(function (f) {
        var b = htmlEl("button", { type: "button", class: "chip-btn" }, box, f.name);
        b.addEventListener("click", function () { show(f, b); });
        b.addEventListener("mouseenter", function () { show(f, b); });
        buttons.push(b);
      });
    });
    var out = htmlEl("div", { class: "cti-out" }, grid);
    htmlEl("b", {}, out, "T");
    htmlEl("span", {}, out, "CTI score from 0 to 1, severity together with confidence in it");
    var detail = htmlEl("div", { class: "cti-detail", "aria-live": "polite" }, host);

    function show(f, b) {
      buttons.forEach(function (x) { x.classList.toggle("is-on", x === b); });
      detail.textContent = "";
      htmlEl("b", {}, detail, f.group + " · " + f.name);
      htmlEl("div", { class: "cti-values" }, detail, f.values);
      htmlEl("div", {}, detail, f.text);
    }
    show(CTI_FACTORS[0], buttons[0]);
  }

  function ctiLines() {
    var e = example(true);
    var w = e.s.weights;
    return [
      { base: w.S * e.S, name: "Burst alone", color: "var(--viz-2)" },
      { base: w.S * e.S + w.A * e.A, name: "Burst + RCF anomaly", color: "var(--viz-3)" }
    ];
  }

  // Smallest T, to two decimals, that lifts the fused example into tier 3
  function ctiThreshold() {
    var s = sc(EXAMPLE.scenario);
    return Math.ceil(((s.tiers[2] - ctiLines()[1].base) / s.weights.T) * 100) / 100;
  }

  function drawCtiEffect(host) {
    var s = sc(EXAMPLE.scenario);
    var W = 600, H = 300, left = 50, right = 160, top = 16, bottom = 46;
    var plotW = W - left - right, plotH = H - top - bottom;
    var x = function (t) { return left + t * plotW; };
    var y = function (r) { return top + (1 - Math.min(1, r)) * plotH; };
    var scroll = htmlEl("div", { class: "viz-scroll" }, host);
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, role: "group", "aria-label": EXAMPLE.scenario + " risk score as the CTI score T grows" }, scroll);

    bands(s.tiers).forEach(function (b) {
      svgEl("rect", { x: left, y: y(b.to), width: plotW, height: y(b.from) - y(b.to), fill: b.fill, opacity: 0.75 }, svg);
      svgEl("text", { x: left + 6, y: y(b.to) + 14, class: "t-strong t-small" }, svg, b.name);
    });
    [0, 0.25, 0.5, 0.75, 1].forEach(function (v) {
      svgEl("text", { x: left - 8, y: y(v) + 4, "text-anchor": "end", class: "t-small" }, svg, String(v));
      svgEl("text", { x: x(v), y: H - bottom + 16, "text-anchor": "middle", class: "t-small" }, svg, String(v));
    });
    svgEl("line", { class: "axis", x1: left, x2: left + plotW, y1: y(0), y2: y(0) }, svg);
    svgEl("text", { x: left + plotW / 2, y: H - 8, "text-anchor": "middle" }, svg, "CTI score T from DECIPHER");
    svgEl("text", { x: 14, y: top + plotH / 2, "text-anchor": "middle", transform: "rotate(-90 14 " + (top + plotH / 2) + ")" }, svg, "Risk score R");

    var LINES = ctiLines();
    LINES.forEach(function (l) {
      var end = l.base + s.weights.T;
      svgEl("line", { x1: x(0), y1: y(l.base), x2: x(1), y2: y(end), stroke: l.color, "stroke-width": 2.5 }, svg);
      svgEl("text", { x: x(1) + 8, y: y(end) + 4, class: "t-strong t-small" }, svg, l.name);
      svgEl("text", { x: x(1) + 8, y: y(end) + 18, class: "t-small" }, svg, "up to " + end.toFixed(3));
    });
    var cross = ctiThreshold();
    if (cross <= 1) {
      svgEl("line", { class: "guide", x1: x(cross), x2: x(cross), y1: y(s.tiers[2]), y2: y(0) }, svg);
      svgEl("text", { x: x(cross) + 4, y: y(0) - 6, class: "t-small" }, svg, "T ≥ " + cross.toFixed(2) + " → T3");
    }

    var guide = svgEl("line", { class: "guide", y1: top, y2: y(0), visibility: "hidden" }, svg);
    var dots = LINES.map(function (l) { return svgEl("circle", { r: 5, fill: l.color, stroke: "#fff", "stroke-width": 2, visibility: "hidden" }, svg); });
    var overlay = svgEl("rect", { x: left, y: top, width: plotW, height: plotH, fill: "transparent" }, svg);
    function readout(ev) {
      var pt = svg.createSVGPoint();
      pt.x = ev.clientX; pt.y = ev.clientY;
      var p = pt.matrixTransform(svg.getScreenCTM().inverse());
      var t = Math.max(0, Math.min(1, Math.round(((p.x - left) / plotW) * 100) / 100));
      guide.setAttribute("x1", x(t)); guide.setAttribute("x2", x(t)); guide.setAttribute("visibility", "visible");
      var lines = ["T = " + fmt(t)];
      LINES.forEach(function (l, i) {
        var r = l.base + s.weights.T * t;
        dots[i].setAttribute("cx", x(t)); dots[i].setAttribute("cy", y(r)); dots[i].setAttribute("visibility", "visible");
        lines.push(l.name + ": " + r.toFixed(3) + " (T" + tierOf(r, s.tiers) + ")");
      });
      C.fillTip(lines);
      C.placeTip(ev.clientX, ev.clientY);
    }
    overlay.addEventListener("pointermove", readout);
    overlay.addEventListener("pointerenter", readout);
    overlay.addEventListener("pointerleave", function () {
      guide.setAttribute("visibility", "hidden");
      dots.forEach(function (d) { d.setAttribute("visibility", "hidden"); });
      C.hideTip();
    });
  }

  /* ── Who can be blocked: candidates against the gates ── */
  var GATES = [
    { name: "Source", text: "Only the triggering alert's own source IP and user fields. Context events and fusion counterparts never supply targets." },
    { name: "Policy", text: "Tier 2 or 3, a mitigation listed for that tier, and allow_mitigation: true for the scenario." },
    { name: "never_block", text: "Loopback, link-local, multicast, broadcast, the manager's own addresses and anything in global.never_block." },
    { name: "Allowlists", text: "Scanner allowlist (unreadable file means decline), protected_users (root always), terminable_services." }
  ];

  function candidates() {
    return [
      { name: EXAMPLE.ip + ", source IP of the alert", stop: -1, out: "firewall-drop runs." },
      { name: EXAMPLE.user + ", user named in the alert", stop: -1, out: "lock_user_linux.sh runs at tier 3." },
      { name: "198.51.100.7, IP seen in a context event", stop: 0, out: "Context events cover every log on the agent; a bystander could be hit." },
      { name: "User from the fused anomaly alert", stop: 0, out: "A counterpart raises the score, never the target list." },
      { name: "Alert source IP with allow_mitigation: false", stop: 1, out: "Logged as withheld_reason: mitigation_disabled." },
      { name: "The Wazuh manager's own address", stop: 2, out: "Refused: never_block." },
      { name: "root, named in the alert", stop: 3, out: "root is always protected." },
      { name: "A scanner on the allowlist", stop: 3, out: "Allowlisted sources still alert, but are never blocked." }
    ];
  }

  function drawBlast(host) {
    var grid = htmlEl("div", { class: "blast" }, host);
    var list = htmlEl("div", { class: "blast-list", role: "group", "aria-label": "Candidate targets" }, grid);
    htmlEl("div", { class: "j-side-title" }, list, "Pick a candidate target");
    var gates = htmlEl("ol", { class: "blast-gates" }, grid);
    var gateEls = GATES.map(function (g, i) {
      var li = htmlEl("li", {}, gates);
      htmlEl("b", {}, li, (i + 1) + ". " + g.name);
      htmlEl("span", {}, li, g.text);
      return li;
    });
    var verdict = htmlEl("li", { class: "blast-verdict" }, gates);
    var cands = candidates();
    var btns = cands.map(function (c) {
      var b = htmlEl("button", { type: "button", class: "chip-btn" }, list, c.name);
      b.addEventListener("click", function () { pick(c, b); });
      return b;
    });
    function pick(c, b) {
      btns.forEach(function (x) { x.classList.toggle("is-on", x === b); });
      gateEls.forEach(function (el, i) {
        el.classList.toggle("is-pass", c.stop === -1 || i < c.stop);
        el.classList.toggle("is-stop", i === c.stop);
        el.classList.toggle("is-skip", c.stop !== -1 && i > c.stop);
      });
      verdict.className = "blast-verdict " + (c.stop === -1 ? "is-pass" : "is-stop");
      verdict.textContent = (c.stop === -1 ? "Acted on. " : "Not touched. ") + c.out;
    }
    pick(cands[0], btns[0]);
  }

  /* ── Tables and text filled from the config ── */
  function fillWeightsTable(tbody) {
    names().forEach(function (n) {
      var s = sc(n), tr = htmlEl("tr", {}, tbody);
      code(htmlEl("td", {}, tr), n);
      htmlEl("td", {}, tr, TYPE_LABEL[s.type]);
      ["A", "S", "T"].forEach(function (k) { htmlEl("td", { class: "num" }, tr, String(s.weights[k])); });
      htmlEl("td", { class: "num" }, tr, s.tiers.join(" / "));
      htmlEl("td", {}, tr, decipherStatus(n));
    });
  }

  function fillTierActions(tbody) {
    var s = sc(EXAMPLE.scenario), b = s.tiers;
    var ranges = ["below " + b[0], b[0] + " to " + b[1], b[1] + " to " + b[2], b[2] + " and above"];
    [0, 1, 2, 3].forEach(function (t) {
      if (t === 0 && b[0] <= 0) return;
      var tr = htmlEl("tr", {}, tbody);
      htmlEl("td", {}, tr, "T" + t);
      htmlEl("td", { class: "num" }, tr, ranges[t]);
      htmlEl("td", {}, tr, t >= 1 ? "yes" : "no");
      htmlEl("td", {}, tr, t >= 1 ? priority(t).replace("priority-level:", "priority ") : "no");
      var cell = htmlEl("td", {}, tr);
      var p = planned(s, t);
      if (!p.length) cell.textContent = t === 0 ? "none, decision logged" : "none";
      p.forEach(function (m, i) { if (i) cell.appendChild(document.createTextNode(" + ")); code(cell, m); });
    });
  }

  function fillAnalyzeEndpoints(cell) {
    wired().forEach(function (n, i) {
      if (i) htmlEl("br", {}, cell);
      code(cell, "POST " + sc(n).decipher_endpoint);
    });
  }

  function fillScenarioList(span) {
    wired().forEach(function (n, i, all) {
      if (i) span.appendChild(document.createTextNode(i === all.length - 1 ? " and " : ", "));
      code(span, n);
    });
  }

  function fillNeverBlock(span) {
    CFG.never_block_defaults.forEach(function (c, i) {
      if (i) span.appendChild(document.createTextNode(", "));
      code(span, c);
    });
  }

  function journeyTakeaway() {
    var on = example(false), off = example(true);
    return on.tier !== off.tier
      ? "Threat intelligence moves this alert from tier " + off.tier + " to tier " + on.tier + ". Losing DECIPHER lowers the score, but never stops the pipeline."
      : "Losing DECIPHER lowers the score, but never stops the pipeline.";
  }

  var TEXT = {
    "cti-threshold": function () { return ctiThreshold().toFixed(2); },
    "journey-takeaway": journeyTakeaway,
    "example-user": function () { return EXAMPLE.user; },
    "t3-line": function () { return String(sc(EXAMPLE.scenario).tiers[2]); }
  };

  var FILL = {
    "weights-table": fillWeightsTable,
    "tier-actions": fillTierActions,
    "analyze-endpoints": fillAnalyzeEndpoints,
    "wired-scenarios": fillScenarioList,
    "never-block": fillNeverBlock
  };

  var DRAW = { arch: drawArch, "scenario-types": drawScenarioTypes, detectors: drawDetectors, journey: drawJourney,
    playground: drawPlayground, "cti-factors": drawCtiFactors, "cti-effect": drawCtiEffect, blast: drawBlast };

  function render() {
    document.querySelectorAll("[data-viz]").forEach(function (host) {
      var draw = DRAW[host.getAttribute("data-viz")];
      if (draw) draw(host);
    });
    document.querySelectorAll("[data-fill]").forEach(function (el) {
      var fill = FILL[el.getAttribute("data-fill")];
      if (fill) { el.textContent = ""; fill(el); }
    });
    document.querySelectorAll("[data-text]").forEach(function (el) {
      var text = TEXT[el.getAttribute("data-text")];
      if (text) el.textContent = text();
    });
  }

  function failed(err) {
    document.querySelectorAll("[data-viz], [data-fill]").forEach(function (host) {
      host.textContent = "";
      htmlEl("p", { class: "rd-note" }, host, "Could not load RADAR's config (" + err + "). Check that assets/radar-config.js is present; regenerate it with docs/website/tools/build_radar_config.py.");
    });
  }

  function init() {
    // radar-config.js sets window.RADAR_CONFIG, which also works from file://.
    // The fetch is a fallback for a page that loads only the JSON.
    if (window.RADAR_CONFIG) { CFG = window.RADAR_CONFIG; render(); return; }
    fetch(CONFIG_URL)
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (cfg) { CFG = cfg; render(); })
      .catch(function (err) { failed(err.message || String(err)); });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
