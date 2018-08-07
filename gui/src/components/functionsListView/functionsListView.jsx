import React, {Component} from 'react';
import List from 'react-list-select'

import './functionListView.css'

class FunctionsListView extends Component {
  constructor(props) {
    super(props);
    if (this.props.functions === undefined) {
      console.error("FunctionsListView not passed required prop: functions");
      debugger
    }

    this.state = {
      functions: this.props.functions,
      functions_names: this.props.functions.map((func) => {
        if (func.name === "") {
          return `sub_${func.address.toString(16)}`
        } else {
          return func.name
        }
      }),
      selected_function: 0
    }
    // bind functions that need to be bound to get acess to this
    this.handleOnChange = this.handleOnChange.bind(this)
  }
  handleOnChange(selected) {
    if (this.props.onChange === undefined) {
      return
    }
    this.props.onChange(selected);
    this.setState({selected_function: selected})
  }
  render() {
    // slected{} is a prop that takes a list of indicies to mark as selected in the list
    return ( //

        <div className="FunctionsListView">
          <List items={this.state.functions_names} selected={[this.state.selected_function]} onChange={this.handleOnChange}/>
        </div>);
  }
}

export default FunctionsListView;
