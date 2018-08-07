import React, { PureComponent } from 'react';

export default class InstructionComment extends PureComponent {
  render() {
    const { instruction } = this.props
    if (instruction.detail.length > 0 && instruction.detail[0].contents) {
      return (
        <span className="detail">
          &emsp;
          ;
          {instruction.detail[0].contents}
        </span>
      )
    } else {
      return null
    }
  }
}
