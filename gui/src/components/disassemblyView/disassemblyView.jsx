import React, {Component} from 'react';
import List from 'react-list-select'
import CFGView from '../CFG/CFGView'
import FunctionsListView from '../functionsListView/functionsListView'
import LinearDisassemblyView from '../linearDisassemblyView/linearDisassemblyView'
import InfoView from '../infoView/infoView'
import uploadFileToDisassemble from '../../services/api-consumer/api-consumer'
import jsonTransform from '../../json_transform'
import graphify from '../../graphify'

import './disassemblyView.css'
class DisassemblyView extends Component {
  constructor(props) {
    super(props)
    this.state = {
      graph: undefined,
      functions: undefined,
      disasm: undefined,
      info: undefined,
      selectedFunction: undefined,
      selectedView: "Info"
    }
    this.avaliableViews = ["Graph", "Linear", "Info"]
    this.handleViewSelection = this.handleViewSelection.bind(this)
  }
  getData() {

    if (this.props.location.state && this.props.location.state.files && this.props.location.state.files.length > 0) {
      var resp = uploadFileToDisassemble(this.props.location.state.files[0])
      resp.then((result) => {
        if (result === undefined) {
          debugger;
          return;
        }
        var AllFunctions = jsonTransform(result.disasm, result.functions, this.state.selectedFunction);
        var funcData = AllFunctions[this.state.selectedFunction];

        if (this.state.selectedFunction === undefined || this.state.selectedFunction === "EntryPoint") {
            funcData = AllFunctions[result.functions.find(function(descriptor) {
              return descriptor.name === 'EntryPoint'
            }).address];
        }
        //console.log(funcData);
        var temp_graph = graphify(funcData);
        //var temp_graph = graphify(jsonTransform(result.disasm, result.functions, this.state.selectedFunction))
        var temp_functions = [];
        temp_functions = result.functions.filter((func) => {
          return func.mem_type === "Image"
        })
        const entryPoint = result.functions[0]
        this.setState({
          graph: temp_graph,
          functions: temp_functions,
          allFunctions: AllFunctions,
          disasm: result.disasm,
          selectedFunction: entryPoint,
          info: result.info
        })
      });
    }
  }
  componentWillMount() {
    if (this.state.graph === undefined) {
      this.getData()
    }
  }
  functionsListChangeHandler(func) {

    var funcData = this.state.allFunctions[this.state.functions[func].address];
    //console.log(this.state.functions[func]);
    this.setState({
      selectedFunction: this.state.functions[func],
      graph: graphify(funcData)
    });
    if (this.state.selectedView === "Info") {
      this.setState({selectedView: "Graph"})
    }
  }
  functionByAddress(address) {
    const {functions} = this.state
    return functions.find()

  }
  userSelectedFunctionHandler(functionAddress, hexAddress) {
    const ordinalAddress = Number.parseInt(hexAddress, 10)
    this.setState({selectedFunction: this.functionByAddress(ordinalAddress)})
    console.log("Called userSelectedFunctionHandler");
    console.log("functionAddress: ", functionAddress);
    console.log("selectedAddress: ", hexAddress);
    console.log(this.state.functions.indexOf(functionAddress));
  }
  handleViewSelection(selected) {
    this.setState({selectedView: this.avaliableViews[selected]})
  }
  render() {

    if (!this.state.graph) {
      return ( //
          <div className="loader"></div>)
    } else {
      // FIXME: do this in the router instead and add redux or sm. yolo
      var viewToRender = undefined;
      if (this.state.selectedView === "Graph") {
        viewToRender = (<CFGView graph={this.state.graph} selectedFunction={this.state.selectedFunction}/>)
      } else if (this.state.selectedView === "Info") {
        viewToRender = (<InfoView info={this.state.info}/>)
      } else if (this.state.selectedView === "Linear") {
        viewToRender = (
          <LinearDisassemblyView
            selectedFunction={this.state.selectedFunction}
            disassembly={this.state.disasm}
          />
        )
      }
      return (
          <div className="DisassemblyView">            
            <div className="row">             
              <FunctionsListView
                className="col"
                functions={this.state.functions}
                onChange={this.functionsListChangeHandler.bind(this)}
              />
              {viewToRender}
            </div>
            <div className="bottombar">
              <List items={this.avaliableViews} selected={[this.avaliableViews.indexOf(this.state.selectedView)]} onChange={this.handleViewSelection}/>
            </div>
          </div>)
    }
  }
}

export default DisassemblyView;
