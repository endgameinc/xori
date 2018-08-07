import * as d3 from 'd3'
import React from 'react'
import dagreD3 from 'dagre-d3'
import './CFGView.css'
import classnames from 'classnames'

import * as Mnemonics from '../linearDisassemblyView/mnemonic'
export default class CFGView extends React.PureComponent {
  cleanOldGraph() {
    console.log('clearing graph')
    var svg = d3.select("svg");
    svg.call(d3.zoom().transform, d3.zoomIdentity);
    svg.select("g").remove();


  }
  zoom_actions() {
    d3.select("svg").select("g").attr("transform", d3.event.transform)
  }
  drawGraph(graph, selectedFunction) {
    this.cleanOldGraph();
    console.log("draw graph was called")
    // Create the input graph
    var dagre_graph = new dagreD3.graphlib.Graph({directed: true, multigraph: true}).setGraph({}).setDefaultEdgeLabel(function() {
      return {};
    });

    // Layout graph with options
    dagre_graph.graph().ranker = "shortest-path"
    dagre_graph.graph().edge = "shortest-path"
    dagre_graph.graph().ranksep = 10;
    dagreD3.dagre.layout(dagre_graph);

    // Create the renderer
    var render = new dagreD3.render();

    // Set up an SVG group so that we can translate the final graph.
    var svg = d3.select("svg") //set the height and width properties of the svg
      .attr("height", window.innerHeight) // so it doesn't resize on us
      .attr("width", window.innerWidth);

    // add radial gradiant
    var linearGradient = svg.append("defs")
      .append("linearGradient")
        .attr("id", "linear-gradient")
        .attr("y2", "1")
        .attr("y1", "0")
        .attr("x1", "0")
        .attr("x2", "0");


    linearGradient.append("stop")
        .attr("offset", "0%")
        .attr("stop-color", "#29282d");

    linearGradient.append("stop")
        .attr("offset", "100%")
        .attr("stop-color", "#363443");

    // create group for pan and zoom
    var svg_group = svg.append("g");
    svg.call(d3.zoom().on("zoom",this.zoom_actions));
    // this.zoom_actions()
    // register zoom handler
    // var zoom_handler = d3.zoom().on("zoom", zoom_actions);
    // zoom_handler(svg);
    // disable double click
    svg.on("dblclick.zoom", null)

    // stop event propgation when user selects our group so text selection works
    svg_group.on("mousedown", function() {
      d3.event.stopPropagation();
    });

    // Fix the arrows so theyre not huge
    // Add our custom arrow (a hollow-point)
    render.arrows().cfgarrow = function normal(parent, id, edge, type) {
      var marker = parent.append("marker")
        .attr("id", id)
        .attr("viewBox", "0 0 10 20")
        .attr("refX", 10)
        .attr("refY", 5)
        .attr("markerHeight", 5)
        .attr("orient", "auto");

      var path = marker.append("path")
        .attr("d", "M 0 0 L 15 5 L 0 10")
        .style("stroke-width", 1)
        .style("stroke-dasharray", "1,0");
      dagreD3.util.applyStyle(path, edge[type + "Style"]);
    };

    // Add all the nodes and links to the graph
    graph.nodes.map((node) => {
      var nodecontent = ""
      // generate the text that goes inside each node (addresses, instructions, comments)
      node.instructions.map((instruction) => {
        var addr = `<div style="display: inline-block; width: 130px;" class="address">0x${instruction.instr.address.toString(16)}: </div>`

        var mnemonic = `<div style="display: inline-block; width: 120px;" class=${ classnames({
        call: Mnemonics.callMnemonics.has(instruction.instr.mnemonic),
        mov: Mnemonics.movMnemonics.has(instruction.instr.mnemonic),
        logic: Mnemonics.logicMnemonics.has(instruction.instr.mnemonic),
        math: Mnemonics.mathMnemonics.has(instruction.instr.mnemonic),
        mnemonic: Mnemonics.otherMnemonicTypes.has(instruction.instr.mnemonic) === false,
        }) }>${instruction.instr.mnemonic}&nbsp;</div>`


        var op_str = `<div style="display: inline-block;" class="op_str"> ${instruction.instr.op_str}&nbsp;</div>`
        var detail = ""
        // if a node has a comment, add that in too
        if (instruction.detail.length > 0 && instruction.detail[0].contents)
          detail += `<div style="display: inline-block; width: 300px; overflow: hidden; white-space: nowrap; text-overflow: ellipsis;" class="detail">;${instruction.detail[0].contents}</div>`
        nodecontent += `
          <div>
            ${addr}${mnemonic}${op_str}${detail}
          </div>\n`
      })

      var isPushEbp = ``;
      if(selectedFunction !== undefined && node.start === selectedFunction.address){
        isPushEbp = `<div style="display: inline-block; width: 100%;" class="firstBasicBlockHeader"> ${node.name} </div>`;
      }
      // populate the node with it's content we just generated.
      dagre_graph.setNode((+node.id), {
        label: `
                ${isPushEbp}
                <div class="node-info">
                  ${nodecontent}
                </div>`,
        labelType: "html"
      })
    })
    // iterate through all of the links and add the links to each node.
    graph.links.map((link) => {
      const stroke_color = link.type === "right"
        ? "var(--positive-link-color)"
        : "var(--negative-link-color)"
      dagre_graph.setEdge("" + link.source, "" + link.target, {
        label: link.type === "right"
          ? "+"
          : "-",
        name: link.type,
        arrowhead: "cfgarrow",
        arrowheadStyle: `fill: ${stroke_color};`,
        markerWidth: "2",
        markerHeight: "2",
        style: `stroke:${stroke_color};`
      })
    });

    dagre_graph.nodes().forEach(function(v) {
      if (v === undefined) {
        console.error("v was undefined: ", graph);
        debugger;
        return;
      }
      var node = dagre_graph.node((+v));
      if (node === undefined) {
        // FIXME: grease over trying to acess a non graph member by just adding it anyway ¯\_(ツ)_/¯
        dagre_graph.setNode(v, {
          label: `<div class="node-info"><div><div style="display: inline-block; width: 130px;" class="address">0x${(+v).toString(16)}: </div><div style="display: inline-block; width: 70px;" class="mnemonic">missingno </div><div style="display: inline-block;" class="op_str">id: ${v}</div></div></div>`,
          labelType: "html"
        })
        console.error("node was undefined", graph, v, node)
        node = dagre_graph.node(v);
      }
      // Round the corners of the nodes
      node.rx = node.ry = 2;
    });

    // Run the renderer. This is what draws the final graph.
    render(d3.select("svg g"), dagre_graph);

    // Center the graph
    var xCenterOffset = (svg.attr("width") - dagre_graph.graph().width) / 2;
    svg_group.attr("transform", "translate(" + xCenterOffset + ", 20)");
    var centeredTransform = d3.zoomIdentity.translate(xCenterOffset,20)
    svg.call(d3.zoom().transform, centeredTransform )

  }
  // things that happen the first time the graph is drawn
  componentDidMount() {
    if (this.props.graph) {
      this.drawGraph(this.props.graph, this.props.selectedFunction);
    }
  }
  componentWillReceiveProps(nextProps, currentProps) {

    this.drawGraph(nextProps.graph, nextProps.selectedFunction)
  }
  render() {
    if (!this.props.graph) {
      return <h1>Loading...</h1>
    } else {
      return ( //
          <div className="CFGView">
            <svg width={window.innerWidth} height={window.innerHeight}/>
          </div>)
    }
  }
}
