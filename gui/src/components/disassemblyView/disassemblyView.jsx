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
        var allFunctions = jsonTransform(result.disasm, result.functions, this.state.selectedFunction);
        var funcData = allFunctions[this.state.selectedFunction];
        if (this.state.selectedFunction === undefined || this.state.selectedFunction === "EntryPoint") {
            funcData = allFunctions[result.functions.find(function(descriptor) {
              return descriptor.name === 'EntryPoint'
            }).address];
        }
        var tempGraph = graphify(funcData);
        var tempFunctions = [];
        tempFunctions = result.functions.filter((func) => {
          return func.mem_type === "Image"
        })
        const entryPoint = result.functions[0]
        this.setState({
          graph: tempGraph,
          functions: tempFunctions,
          allFunctions: allFunctions,
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
    this.setState({
      selectedFunction: this.state.functions[func],
      graph: graphify(funcData)
    });
    if (this.state.selectedView === "Info") {
      this.setState({selectedView: "Graph"})
    }
  }
  functionByAddress(address) {
    var report = undefined
    this.state.functions.forEach( (f) => {
      if(address == f.address){
        report = f;
      }
    })
    return report;
  }
  userSelectedFunctionHandler(ownedFunctionAddress,ordinalInstructionAddress) {
    const tempSelectedFunction = this.functionByAddress(ownedFunctionAddress);
    if(tempSelectedFunction === undefined){
      alert(`Instruction does not belong to any known function.`);
      return;
    }
    this.setState({
      selectedFunction: tempSelectedFunction,
      graph: graphify(this.state.allFunctions[tempSelectedFunction.address]),
      })
  }
  handleViewSelection(selected) {
    this.setState({selectedView: this.avaliableViews[selected]})
  }
  render() {

    if (!this.state.graph) {
      return (
          <div className="loader"></div>)
    } else {
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
            onChange={this.userSelectedFunctionHandler.bind(this)}
          />
        )
      }
      return (
          <div className="DisassemblyView">
            <div className="row">
              <FunctionsListView
                functions={this.state.functions}
                onChange={this.functionsListChangeHandler.bind(this)}
                selectedFunction={this.state.selectedFunction}
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
