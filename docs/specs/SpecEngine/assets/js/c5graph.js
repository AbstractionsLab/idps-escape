/* c5graph.js — Interactive Cytoscape.js graph logic for specs-graph.html
 *
 * Two sentinel tokens are replaced by c5graph.py at generation time:
 *   __NODES_JSON__  →  JSON array of Cytoscape node elements
 *   __EDGES_JSON__  →  JSON array of Cytoscape edge elements
 *
 * Each node carries: { id, label, fullLabel, prefix, covered }
 * Each edge carries: { id, source, target }
 *
 * Graph conventions:
 *   - Green node  = covered (has at least one upward link)
 *   - Yellow node = uncovered (no upward links; root item)
 *   - Edges run child → parent (upward traceability)
 *   - Initial view: MRS root nodes + their direct children
 *   - Click a node to expand its direct children; click again to collapse
 */

(function () {
  'use strict';

  /* -----------------------------------------------------------------------
   * Data embedded at generation time
   * --------------------------------------------------------------------- */
  var ALL_NODES = __NODES_JSON__;
  var ALL_EDGES = __EDGES_JSON__;

  /* Build lookup maps */
  var nodeMap = {};
  ALL_NODES.forEach(function (n) { nodeMap[n.data.id] = n.data; });

  /*
   * parent_of[uid]   = [parentUID, ...]  — upward edge targets
   * children_of[uid] = [childUID,  ...]  — reverse edges (items whose link
   *                                        points to uid as parent)
   */
  var parent_of   = {};
  var children_of = {};
  ALL_NODES.forEach(function (n) {
    parent_of[n.data.id]   = [];
    children_of[n.data.id] = [];
  });
  ALL_EDGES.forEach(function (e) {
    parent_of[e.data.source].push(e.data.target);
    children_of[e.data.target].push(e.data.source);
  });

  /* -----------------------------------------------------------------------
   * Cytoscape initialisation
   * --------------------------------------------------------------------- */
  if (typeof cytoscapeDagre !== 'undefined') {
    cytoscape.use(cytoscapeDagre);
  }

  var cy = cytoscape({
    container: document.getElementById('cy'),
    style: [
      {
        selector: 'node',
        style: {
          'background-color': function (ele) {
            return ele.data('covered') ? '#27ae60' : '#f1c40f';
          },
          'border-width': 2,
          'border-color': function (ele) {
            return ele.data('covered') ? '#1e8449' : '#d4ac0d';
          },
          'label': 'data(label)',
          'font-size': '9px',
          'text-valign': 'bottom',
          'text-halign': 'center',
          'text-margin-y': 4,
          'color': '#dde',
          'width': 28,
          'height': 28,
          'text-wrap': 'wrap',
          'text-max-width': '110px',
          'text-overflow-wrap': 'whitespace',
        }
      },
      {
        selector: 'node:selected',
        style: {
          'border-width': 3,
          'border-color': '#74b9ff',
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 1.5,
          'line-color': '#3a4a6a',
          'target-arrow-color': '#3a4a6a',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'arrow-scale': 0.7,
          'opacity': 0.7,
        }
      },
    ],
    elements: [],
    layout: { name: 'preset' },
  });

  /* -----------------------------------------------------------------------
   * Expand / collapse state
   * --------------------------------------------------------------------- */
  var expanded = new Set(); /* UIDs whose children have been added */
  var visible  = new Set(); /* UIDs currently rendered in the graph */

  function runLayout() {
    var layoutName = (typeof cytoscapeDagre !== 'undefined') ? 'dagre' : 'breadthfirst';
    cy.layout({
      name:     layoutName,
      rankDir:  'TB',
      nodeSep:  50,
      rankSep:  70,
      padding:  30,
      animate:  false,
    }).run();
    cy.fit(undefined, 30);
  }

  function addNode(uid) {
    if (visible.has(uid) || !nodeMap[uid]) return;
    visible.add(uid);
    cy.add({ group: 'nodes', data: nodeMap[uid] });
  }

  function addEdgeIfBothVisible(src, tgt) {
    if (!visible.has(src) || !visible.has(tgt)) return;
    var eid = src + '__' + tgt;
    if (!cy.getElementById(eid).length) {
      cy.add({ group: 'edges', data: { id: eid, source: src, target: tgt } });
    }
  }

  /**
   * Recursively collect descendants of `uid` that can be removed —
   * i.e. nodes whose every visible parent is also being removed.
   * Cytoscape automatically removes connected edges when a node is removed.
   */
  function removeSubtree(uid) {
    var toRemove = new Set();

    function collect(u) {
      (children_of[u] || []).forEach(function (child) {
        var allParentsGone = (parent_of[child] || []).every(function (p) {
          return toRemove.has(p) || !visible.has(p);
        });
        if (allParentsGone && visible.has(child)) {
          toRemove.add(child);
          expanded.delete(child);
          collect(child);
        }
      });
    }

    collect(uid);
    toRemove.forEach(function (u) {
      cy.getElementById(u).remove();
      visible.delete(u);
    });
    expanded.delete(uid);
  }

  function expandNode(uid) {
    if (expanded.has(uid)) return;
    expanded.add(uid);
    (children_of[uid] || []).forEach(function (child) {
      addNode(child);
      addEdgeIfBothVisible(child, uid);
      /* Reconnect any other already-visible parents of this child */
      (parent_of[child] || []).forEach(function (p) {
        addEdgeIfBothVisible(child, p);
      });
    });
    runLayout();
  }

  function collapseNode(uid) {
    if (!expanded.has(uid)) return;
    removeSubtree(uid);
    runLayout();
  }

  /* -----------------------------------------------------------------------
   * Initial view: MRS root nodes + their direct children
   * --------------------------------------------------------------------- */
  function initView() {
    /* Uncovered MRS nodes are the document-level roots */
    var mrsRoots = ALL_NODES.filter(function (n) {
      return n.data.prefix === 'MRS' && !n.data.covered;
    });
    /* Fallback: all uncovered nodes (e.g. no MRS prefix present) */
    var roots = mrsRoots.length
      ? mrsRoots
      : ALL_NODES.filter(function (n) { return !n.data.covered; });

    roots.forEach(function (n) { addNode(n.data.id); });

    roots.forEach(function (n) {
      var uid = n.data.id;
      expanded.add(uid);
      (children_of[uid] || []).forEach(function (child) {
        addNode(child);
        addEdgeIfBothVisible(child, uid);
      });
    });

    runLayout();
  }

  initView();

  /* -----------------------------------------------------------------------
   * Click handler: expand / collapse on tap
   * --------------------------------------------------------------------- */
  cy.on('tap', 'node', function (evt) {
    var uid = evt.target.data('id');
    if (expanded.has(uid)) {
      collapseNode(uid);
    } else {
      expandNode(uid);
    }
  });

  /* -----------------------------------------------------------------------
   * Hover tooltip
   * --------------------------------------------------------------------- */
  var tooltip   = document.getElementById('tooltip');
  var cyWrapper = document.getElementById('cy-wrapper');

  function escHtml(s) {
    return String(s)
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/"/g,  '&quot;');
  }

  cy.on('mouseover', 'node', function (evt) {
    var d = evt.target.data();
    tooltip.innerHTML =
      '<div class="tt-uid">'    + d.id    + '</div>' +
      '<div class="tt-prefix">' + d.prefix + '</div>' +
      '<div class="tt-label">'  + escHtml(d.fullLabel) + '</div>' +
      '<div class="tt-label" style="color:#aaa;font-size:0.72rem;margin-top:4px;">' +
        (d.covered
          ? '&#9679; covered (has upward link)'
          : '&#9679; uncovered (no upward link)') +
      '</div>';
    tooltip.style.display = 'block';
    positionTooltip(evt.originalEvent);
  });

  cy.on('mousemove', 'node', function (evt) { positionTooltip(evt.originalEvent); });
  cy.on('mouseout',  'node', function ()    { tooltip.style.display = 'none'; });

  function positionTooltip(e) {
    var rect = cyWrapper.getBoundingClientRect();
    var x = e.clientX - rect.left + 14;
    var y = e.clientY - rect.top  + 14;
    var tw = tooltip.offsetWidth  || 280;
    var th = tooltip.offsetHeight || 80;
    if (x + tw > rect.width)  x = e.clientX - rect.left - tw - 10;
    if (y + th > rect.height) y = e.clientY - rect.top  - th - 10;
    tooltip.style.left = x + 'px';
    tooltip.style.top  = y + 'px';
  }

  /* -----------------------------------------------------------------------
   * Toolbar buttons
   * --------------------------------------------------------------------- */
  document.getElementById('btn-expand-all').addEventListener('click', function () {
    ALL_NODES.forEach(function (n) {
      if (!visible.has(n.data.id)) addNode(n.data.id);
    });
    ALL_EDGES.forEach(function (e) {
      addEdgeIfBothVisible(e.data.source, e.data.target);
    });
    ALL_NODES.forEach(function (n) { expanded.add(n.data.id); });
    runLayout();
  });

  document.getElementById('btn-reset').addEventListener('click', function () {
    cy.elements().remove();
    visible.clear();
    expanded.clear();
    initView();
  });

  document.getElementById('btn-fit').addEventListener('click', function () {
    cy.fit(undefined, 30);
  });

  document.getElementById('btn-png').addEventListener('click', function () {
    var png = cy.png({ scale: 2, bg: '#1a1a2e' });
    var a   = document.createElement('a');
    a.href     = png;
    a.download = 'specs-graph.png';
    a.click();
  });

  /* ---- Search / highlight ---- */
  var searchTimeout = null;
  document.getElementById('search-box').addEventListener('input', function () {
    clearTimeout(searchTimeout);
    var q = this.value.trim().toLowerCase();
    searchTimeout = setTimeout(function () {
      cy.nodes().removeClass('search-match search-dim');
      if (!q) return;
      cy.nodes().forEach(function (n) {
        var hit = n.data('id').toLowerCase().includes(q) ||
                  n.data('fullLabel').toLowerCase().includes(q);
        n.addClass(hit ? 'search-match' : 'search-dim');
      });
    }, 200);
  });

  cy.style()
    .selector('node.search-match').style({
      'border-color':      '#74b9ff',
      'border-width':      3,
      'background-color':  '#2980b9',
    })
    .selector('node.search-dim').style({ 'opacity': 0.25 })
    .update();

}());
