/* Charts shared by product-presentation.html and release-notes.html.
   Each <div data-chart="..."> is drawn as inline SVG; styles live in charts.css.
   Sources:
   - sonar-f1: docs/specs/trp/assets/sonar-evaluation/README.md (test split, calibrated decision rule)
   - fusion-weight, fusion-tiers: radar/scenarios/active_responses/ar.yaml (suspicious_login) and
     FusionCorrelator in radar_ar.py (weight = 1 - gap / window_minutes) */
(function () {
  "use strict";

  var NS = "http://www.w3.org/2000/svg";

  function svgEl(name, attrs, parent, text) {
    var node = document.createElementNS(NS, name);
    Object.keys(attrs || {}).forEach(function (k) {
      node.setAttribute(k, attrs[k]);
    });
    if (text !== undefined) node.textContent = text;
    if (parent) parent.appendChild(node);
    return node;
  }

  function htmlEl(name, attrs, parent, text) {
    var node = document.createElement(name);
    Object.keys(attrs || {}).forEach(function (k) {
      node.setAttribute(k, attrs[k]);
    });
    if (text !== undefined) node.textContent = text;
    if (parent) parent.appendChild(node);
    return node;
  }

  function fmt(v) {
    return v.toFixed(2);
  }

  /* ── Tooltip: one per page, text only ── */
  var tip = null;

  function ensureTip() {
    if (tip) return tip;
    tip = htmlEl("div", { class: "viz-tip", role: "tooltip" }, document.body);
    tip.hidden = true;
    return tip;
  }

  function fillTip(lines) {
    ensureTip();
    tip.textContent = "";
    lines.forEach(function (line, i) {
      htmlEl(i === 0 ? "b" : "div", {}, tip, line);
    });
  }

  function placeTip(x, y) {
    tip.hidden = false;
    var w = tip.offsetWidth;
    var h = tip.offsetHeight;
    var left = Math.min(Math.max(8, x + 14), window.innerWidth - w - 8);
    var top = y - h - 12 < 8 ? y + 16 : y - h - 12;
    tip.style.left = left + "px";
    tip.style.top = top + "px";
  }

  function hideTip() {
    if (tip) tip.hidden = true;
  }

  function bindTip(target, lines) {
    target.setAttribute("tabindex", "0");
    target.setAttribute("role", "img");
    target.setAttribute("aria-label", lines.join(". "));
    target.addEventListener("pointerenter", function (e) {
      fillTip(lines);
      placeTip(e.clientX, e.clientY);
    });
    target.addEventListener("pointermove", function (e) {
      placeTip(e.clientX, e.clientY);
    });
    target.addEventListener("pointerleave", hideTip);
    target.addEventListener("focus", function () {
      var r = target.getBoundingClientRect();
      fillTip(lines);
      placeTip(r.left + r.width / 2, r.top);
    });
    target.addEventListener("blur", hideTip);
  }

  window.addEventListener("scroll", hideTip, { passive: true });

  /* ── SONAR detector comparison: grouped lollipops of test F1 ── */
  var BACKENDS = [
    { key: "mvad", name: "MVAD (default)", short: "MVAD", color: "var(--viz-1)" },
    { key: "pca", name: "PCA", short: "PCA", color: "var(--viz-2)" },
    { key: "ewma", name: "EWMA baseline", short: "EWMA", color: "var(--viz-3)" }
  ];

  // [F1, precision, recall, false alarms per day, training time]
  var F1_ROWS = [
    { name: "Resource monitoring", events: 12, r: {
      mvad: [0.96, 0.92, 1.0, 0.52, "233 s"], pca: [0.96, 0.92, 1.0, 0.5, "0.1 s"], ewma: [0.8, 1.0, 0.67, 0.0, "< 1 s"] } },
    { name: "Brute force", events: 8, r: {
      mvad: [0.74, 0.73, 0.75, 0.32, "358 s"], pca: [1.0, 1.0, 1.0, 0.0, "0.1 s"], ewma: [0.35, 0.21, 1.0, 3.0, "< 1 s"] } },
    { name: "Privilege escalation", events: 4, r: {
      mvad: [0.8, 0.67, 1.0, 0.22, "207 s"], pca: [1.0, 1.0, 1.0, 0.0, "0.1 s"], ewma: [0.29, 0.33, 0.25, 0.2, "< 1 s"] } },
    { name: "Lateral movement", events: 4, r: {
      mvad: [0.25, 0.25, 0.25, 0.33, "363 s"], pca: [0.67, 1.0, 0.5, 0.0, "0.1 s"], ewma: [0.5, 0.5, 0.5, 0.2, "< 1 s"] } },
    { name: "RADAR resource data", events: 12, r: {
      mvad: [1.0, 1.0, 1.0, 0.0, "192 s"], pca: [1.0, 1.0, 1.0, 0.0, "< 1 s"], ewma: [0.8, 1.0, 0.67, 0.0, "< 1 s"] } }
  ];

  function drawSonarF1(host) {
    var legend = htmlEl("ul", { class: "viz-legend" }, host);
    BACKENDS.forEach(function (b) {
      var li = htmlEl("li", {}, legend);
      htmlEl("i", { style: "background:" + b.color }, li);
      li.appendChild(document.createTextNode(b.name));
    });

    var W = 900, left = 210, right = 70, top = 14, rowH = 58;
    var plotW = W - left - right;
    var H = top + F1_ROWS.length * rowH + 44;
    var x = function (v) { return left + v * plotW; };
    var offsets = [-14, 0, 14];

    var scroll = htmlEl("div", { class: "viz-scroll" }, host);
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, role: "group", style: "max-width: " + W + "px; min-width: 720px",
      "aria-label": "Test F1 per scenario for the MVAD, PCA and EWMA detectors" }, scroll);

    var bottom = top + F1_ROWS.length * rowH;
    [0, 0.25, 0.5, 0.75, 1].forEach(function (t) {
      svgEl("line", { class: "grid", x1: x(t), x2: x(t), y1: top, y2: bottom }, svg);
      svgEl("text", { x: x(t), y: bottom + 16, "text-anchor": "middle" }, svg, t === 0 || t === 1 ? String(t) : t.toFixed(2));
    });
    svgEl("line", { class: "axis", x1: left, x2: left, y1: top, y2: bottom }, svg);
    svgEl("text", { x: left + plotW / 2, y: bottom + 36, "text-anchor": "middle" }, svg,
      "Test F1 (1.0 = every attack found, no false alarm)");

    F1_ROWS.forEach(function (row, i) {
      var cy = top + i * rowH + rowH / 2;
      if (i > 0) svgEl("line", { class: "grid", x1: 8, x2: W - 8, y1: top + i * rowH, y2: top + i * rowH }, svg);
      svgEl("text", { x: left - 14, y: cy - 2, "text-anchor": "end", class: "t-strong" }, svg, row.name);
      svgEl("text", { x: left - 14, y: cy + 14, "text-anchor": "end", class: "t-small" }, svg, row.events + " attacks in the test split");

      BACKENDS.forEach(function (b, j) {
        var d = row.r[b.key];
        var y = cy + offsets[j];
        svgEl("line", { x1: x(0), x2: x(d[0]), y1: y, y2: y, stroke: b.color, "stroke-width": 2, "stroke-linecap": "round", opacity: 0.55 }, svg);
        svgEl("circle", { cx: x(d[0]), cy: y, r: 5, fill: b.color, stroke: "#fff", "stroke-width": 2 }, svg);
        if (i === 0) {
          svgEl("text", { x: x(d[0]) + 10, y: y + 4, class: "t-small" }, svg, b.short);
        }
        var hit = svgEl("rect", { class: "hit", x: x(0), y: y - 7, width: x(d[0]) - x(0) + 12, height: 14, rx: 4 }, svg);
        bindTip(hit, [
          row.name + " · " + b.name,
          "F1 " + fmt(d[0]) + " (precision " + fmt(d[1]) + ", recall " + fmt(d[2]) + ")",
          d[3].toFixed(2) + " false alarms per day",
          "Training time " + d[4]
        ]);
      });
    });

    var details = htmlEl("details", {}, host);
    htmlEl("summary", {}, details, "Show the numbers");
    var tableWrap = htmlEl("div", { class: "viz-scroll" }, details);
    var table = htmlEl("table", {}, tableWrap);
    var head = htmlEl("tr", {}, htmlEl("thead", {}, table));
    ["Scenario", "Detector", "F1", "Precision", "Recall", "False alarms / day", "Training"].forEach(function (h) {
      htmlEl("th", {}, head, h);
    });
    var body = htmlEl("tbody", {}, table);
    F1_ROWS.forEach(function (row) {
      BACKENDS.forEach(function (b) {
        var d = row.r[b.key];
        var tr = htmlEl("tr", {}, body);
        htmlEl("td", {}, tr, row.name);
        htmlEl("td", {}, tr, b.name);
        htmlEl("td", { class: "num" }, tr, fmt(d[0]));
        htmlEl("td", { class: "num" }, tr, fmt(d[1]));
        htmlEl("td", { class: "num" }, tr, fmt(d[2]));
        htmlEl("td", { class: "num" }, tr, d[3].toFixed(2));
        htmlEl("td", { class: "num" }, tr, d[4]);
      });
    });
  }

  /* ── Fusion: counterpart weight against time ── */
  var FUSION = { window: 30, lead: 10, dataStart: 0, dataEnd: 5 };

  function fusionWeight(t) {
    var start = FUSION.dataStart - FUSION.lead;
    var gap = t < start ? start - t : t > FUSION.dataEnd ? t - FUSION.dataEnd : 0;
    return Math.max(0, 1 - gap / FUSION.window);
  }

  function drawFusionWeight(host) {
    var W = 640, H = 236, left = 48, right = 20, top = 38, plotH = 130;
    var tMin = -46, tMax = 41;
    var plotW = W - left - right;
    var x = function (t) { return left + ((t - tMin) / (tMax - tMin)) * plotW; };
    var y = function (w) { return top + (1 - w) * plotH; };
    var base = y(0);

    var scroll = htmlEl("div", { class: "viz-scroll" }, host);
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, role: "group",
      "aria-label": "Weight of an anomaly counterpart against the time of the signature alert" }, scroll);

    svgEl("rect", { x: x(-10), y: top, width: x(0) - x(-10), height: plotH, fill: "var(--viz-1)", opacity: 0.08 }, svg);
    svgEl("rect", { x: x(0), y: top, width: x(5) - x(0), height: plotH, fill: "var(--viz-1)", opacity: 0.2 }, svg);
    svgEl("text", { x: (x(-10) + x(0)) / 2, y: top - 8, "text-anchor": "middle", class: "t-small" }, svg, "lead 10 min");
    svgEl("text", { x: (x(0) + x(5)) / 2 + 14, y: top - 8, "text-anchor": "start", class: "t-strong t-small" }, svg, "anomaly data window");

    [0, 0.5, 1].forEach(function (w) {
      svgEl("line", { class: "grid", x1: left, x2: W - right, y1: y(w), y2: y(w) }, svg);
      svgEl("text", { x: left - 8, y: y(w) + 4, "text-anchor": "end" }, svg, String(w));
    });
    svgEl("line", { class: "axis", x1: left, x2: W - right, y1: base, y2: base }, svg);

    var pts = [[tMin, 0], [-40, 0], [-10, 1], [5, 1], [35, 0], [tMax, 0]];
    var area = "M" + x(-40) + "," + base + " L" + x(-10) + "," + y(1) + " L" + x(5) + "," + y(1) + " L" + x(35) + "," + base + " Z";
    svgEl("path", { d: area, fill: "var(--viz-1)", opacity: 0.1 }, svg);
    svgEl("polyline", { points: pts.map(function (p) { return x(p[0]) + "," + y(p[1]); }).join(" "),
      fill: "none", stroke: "var(--viz-1)", "stroke-width": 2, "stroke-linejoin": "round" }, svg);

    [-40, -10, 0, 5, 35].forEach(function (t) {
      svgEl("line", { class: "axis", x1: x(t), x2: x(t), y1: base, y2: base + 5 }, svg);
      svgEl("text", { x: x(t), y: base + 18, "text-anchor": "middle" }, svg, t > 0 ? "+" + t : String(t).replace("-", "−"));
    });
    svgEl("text", { x: left + plotW / 2, y: base + 40, "text-anchor": "middle" }, svg,
      "Signature alert time, minutes from the start of the anomaly's data window");

    var dimY = y(0.18);
    svgEl("line", { class: "guide", x1: x(5), x2: x(35), y1: dimY, y2: dimY }, svg);
    svgEl("text", { x: x(16), y: dimY - 6, "text-anchor": "middle", class: "t-small" }, svg, "window_minutes = 30");
    svgEl("line", { class: "guide", x1: x(-40), x2: x(-10), y1: dimY, y2: dimY }, svg);
    svgEl("text", { x: x(-21), y: dimY - 6, "text-anchor": "middle", class: "t-small" }, svg, "window_minutes = 30");

    // Worked example: a burst 2 minutes after the data window
    var ex = 7, exW = fusionWeight(ex);
    svgEl("circle", { cx: x(ex), cy: y(exW), r: 5, fill: "var(--ink, #17212f)", stroke: "#fff", "stroke-width": 2 }, svg);
    svgEl("line", { x1: x(ex) - 2, y1: y(exW) + 6, x2: x(ex) - 8, y2: y(0.42) - 2, stroke: "var(--muted, #3d6363)", "stroke-width": 1 }, svg);
    svgEl("text", { x: x(ex) - 10, y: y(0.42) + 10, "text-anchor": "end", class: "t-strong t-small" }, svg, "burst 2 min later: " + fmt(exW));

    // Hover readout: weight at any signature-alert time
    var guide = svgEl("line", { class: "guide", x1: 0, x2: 0, y1: top, y2: base, visibility: "hidden" }, svg);
    var dot = svgEl("circle", { r: 5, fill: "var(--viz-1)", stroke: "#fff", "stroke-width": 2, visibility: "hidden" }, svg);
    var overlay = svgEl("rect", { x: left, y: top, width: plotW, height: plotH, fill: "transparent" }, svg);

    function readout(e) {
      var pt = svg.createSVGPoint();
      pt.x = e.clientX;
      pt.y = e.clientY;
      var p = pt.matrixTransform(svg.getScreenCTM().inverse());
      var t = Math.round(tMin + ((p.x - left) / plotW) * (tMax - tMin));
      t = Math.max(tMin, Math.min(tMax, t));
      var w = fusionWeight(t);
      guide.setAttribute("x1", x(t));
      guide.setAttribute("x2", x(t));
      dot.setAttribute("cx", x(t));
      dot.setAttribute("cy", y(w));
      guide.setAttribute("visibility", "visible");
      dot.setAttribute("visibility", "visible");
      var when = t < 0 ? Math.abs(t) + " min before the data window starts" : t <= 5 ? "inside the data window" : (t - 5) + " min after the data window ends";
      fillTip(["Weight " + fmt(w), "Signature alert " + when]);
      placeTip(e.clientX, e.clientY);
    }
    overlay.addEventListener("pointermove", readout);
    overlay.addEventListener("pointerenter", readout);
    overlay.addEventListener("pointerleave", function () {
      guide.setAttribute("visibility", "hidden");
      dot.setAttribute("visibility", "hidden");
      hideTip();
    });
  }

  /* ── Fusion: suspicious_login scores on its tier ladder ── */
  var TIERS = [
    { name: "T0", from: 0, to: 0.15, action: "log only", fill: "var(--viz-t0)" },
    { name: "T1", from: 0.15, to: 0.33, action: "email + case", fill: "var(--viz-t1)" },
    { name: "T2", from: 0.33, to: 0.55, action: "+ firewall-drop", fill: "var(--viz-t2)" },
    { name: "T3", from: 0.55, to: 1, action: "+ lock_user_linux.sh", fill: "var(--viz-t3)" }
  ];

  var TIER_POINTS = [
    { r: 0.168, label: "0.168 burst alone", lines: ["Burst alone: 0.168 (T1)", "0.4 × signature 0.42", "No anomaly, no CTI evidence"] },
    { r: 0.384, label: "0.384 burst + off-hour anomaly", lines: ["Burst + off-hour anomaly: 0.384 (T2)", "0.4 × 0.42 + 0.3 × anomaly 0.72", "Anomaly 0.72 = grade 0.8 × confidence 0.9"] },
    { r: 0.468, label: "0.468 any signature alert alone, CTI 1.0", lines: ["Highest single signature alert: 0.468 (T2)", "0.4 × 0.42 + 0.3 × CTI 1.0", "Without fusion, T3 is out of reach"] },
    { r: 0.552, label: "0.552 burst + anomaly + CTI 0.56", strong: true, lines: ["Fused, with CTI: 0.552 (T3)", "0.4 × 0.42 + 0.3 × 0.72 + 0.3 × CTI 0.56", "Locks only the user named in the alert"] }
  ];

  function drawFusionTiers(host) {
    var W = 640, H = 224, left = 24, right = 24, bandY = 140, bandH = 30;
    var plotW = W - left - right;
    var x = function (v) { return left + v * plotW; };

    var scroll = htmlEl("div", { class: "viz-scroll" }, host);
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, role: "group",
      "aria-label": "suspicious_login risk scores placed on its response tiers" }, scroll);

    TIERS.forEach(function (t, i) {
      svgEl("rect", { x: x(t.from) + (i ? 1 : 0), y: bandY, width: x(t.to) - x(t.from) - (i ? 1 : 0), height: bandH, fill: t.fill }, svg);
      svgEl("text", { x: x(t.from) + 6, y: bandY + 19, class: "t-strong t-small" }, svg, t.name);
      svgEl("text", { x: x(t.from) + 28, y: bandY + 19, class: "t-small", style: "fill: var(--ink, #17212f)" }, svg, t.action);
    });
    [0, 0.15, 0.33, 0.55, 1].forEach(function (v) {
      svgEl("text", { x: x(v), y: bandY + bandH + 16, "text-anchor": v === 0 ? "start" : v === 1 ? "end" : "middle" }, svg, String(v));
    });
    svgEl("text", { x: left + plotW / 2, y: bandY + bandH + 38, "text-anchor": "middle" }, svg,
      "Risk score R = 0.3·A + 0.4·S + 0.3·T, suspicious_login weights");

    TIER_POINTS.forEach(function (p, i) {
      var ly = 20 + i * 28;
      var px = x(p.r);
      svgEl("line", { x1: px, x2: px, y1: ly + 6, y2: bandY, stroke: "var(--muted, #3d6363)", "stroke-width": 1 }, svg);
      svgEl("circle", { cx: px, cy: bandY, r: 5, fill: "var(--ink, #17212f)", stroke: "#fff", "stroke-width": 2 }, svg);
      svgEl("text", { x: px + 6, y: ly + 4, class: p.strong ? "t-strong" : "" }, svg, p.label);
      // Hover targets: the label, and the leader down to the dot
      bindTip(svgEl("rect", { class: "hit", x: px - 8, y: ly - 11, width: 16 + p.label.length * 6.6, height: 22, rx: 4 }, svg), p.lines);
      var stem = svgEl("rect", { x: px - 8, y: ly + 11, width: 16, height: bandY - ly - 3, fill: "transparent", style: "cursor: help" }, svg);
      stem.addEventListener("pointerenter", function (e) { fillTip(p.lines); placeTip(e.clientX, e.clientY); });
      stem.addEventListener("pointermove", function (e) { placeTip(e.clientX, e.clientY); });
      stem.addEventListener("pointerleave", hideTip);
    });
  }

  var DRAW = {
    "sonar-f1": drawSonarF1,
    "fusion-weight": drawFusionWeight,
    "fusion-tiers": drawFusionTiers
  };

  function init() {
    document.querySelectorAll("[data-chart]").forEach(function (host) {
      var draw = DRAW[host.getAttribute("data-chart")];
      if (draw) draw(host);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
