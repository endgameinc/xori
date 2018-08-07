import React, { PureComponent } from 'react';
import classnames from 'classnames'
import Mnemonic from './mnemonic'
import InstructionComment from './instruction_comment'
import './linearDisassemblyView.css'
import { AutoSizer, List } from 'react-virtualized';

function ordinalAddressToHexAddress(ordinalAddress) {
  return "0x" + ordinalAddress.toString(16)
}


class LinearDisassemblyView extends PureComponent {
  render() {
    const { selectedFunction, disassembly } = this.props
    const disassemblyEntries = Object.entries(disassembly)
    return (
        <div className="LinearDisassemblyView" ref="scrolling_div">
          <AutoSizer>
            {({ height, width }) => (
              <List
                width={ width }
                height={ height }
                scrollToIndex={ indexOfSelectedFunction() }
                scrollToAlignment={ 'start' }
                rowHeight={ 20 }
                rowCount={disassemblyEntries.length}
                rowRenderer={rowRenderer}
              />
            )}
          </AutoSizer>
        </div>
    );

    function indexOfSelectedFunction() {
      if (selectedFunction === undefined) {
        return undefined
      } else {
        return disassemblyEntries.findIndex(([ address, instruction ]) => {
          return instruction.instr.address === selectedFunction.address
        })
      }
    }
    function rowRenderer({
      index,       // Index of row
      isScrolling, // The List is currently being scrolled
      isVisible,   // This row is visible within the List (eg it is not an overscanned row)
      key,         // Unique key within array of rendered rows
      parent,      // Reference to the parent List (instance)
      style   
    }) {

      const entry = disassemblyEntries[index]
      var id = entry[0]
      var instruction = entry[1]
      var hex_addr = ordinalAddressToHexAddress(instruction.instr.address)
      return (
        <li
          key={key}
          style={ style }
          className={
            classnames({
              selectedInstruction: selectedFunction && hex_addr === ordinalAddressToHexAddress(selectedFunction.address)
            })
          }
        >
          <span className="address" ref={hex_addr}>{hex_addr}:</span>
          &emsp;
          <span className="bytes">
            {instruction.instr.bytes.slice(0,8).reduce((report, current) => report + " " + current.toString(16).padStart(2, "0"), "")}
          </span>
          &emsp;
          <Mnemonic data={ instruction.instr.mnemonic } />
          <span className="op_str">
            {instruction.instr.op_str}
          </span>
          <InstructionComment instruction={ instruction } />
        </li>
      )
    }
  }
}


export default LinearDisassemblyView;
