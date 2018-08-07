import React, { PureComponent } from 'react';
import classnames from 'classnames'

export const movMnemonics = new Set(["mov", "movzx", "push", "lea", "pop", "pushfd","movsx","movd","movups","cmove","movsxd", "movabs", "cmovg", "cmovne"])
export const logicMnemonics = new Set(["xor", "shl", "shr", "ror","rol","and","or","not", "neg", "sar", "sal"])
export const mathMnemonics = new Set(["sub", "add", "div", "mul", "test", "cmp","inc", "dec", "sbb", "imul"])
export const callMnemonics = new Set(["call", "jmp", "ret","retn", "je", "jne", "ja", "jb", "jge", "leave", "jbe", "loop", "jle", "jns","jg", "jae", "js", "jl"])
export const otherMnemonicTypes = new Set([
  ...movMnemonics,
  ...logicMnemonics,
  ...mathMnemonics,
  ...callMnemonics,
])


export default class Mnemonic extends PureComponent {
  render() {
    const { data } = this.props
    return (
      <span className={ classnames({
        call: callMnemonics.has(data),
        mov: movMnemonics.has(data),
        logic: logicMnemonics.has(data),
        math: mathMnemonics.has(data),
        mnemonic: otherMnemonicTypes.has(data) === false,
      }) }>
        {data}&nbsp;
      </span>
    )
  }
}
