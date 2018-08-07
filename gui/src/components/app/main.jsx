import React from 'react'
import {Switch, Route} from 'react-router-dom'
import Splash from '../splash/splash'
import DisassemblyView from '../disassemblyView/disassemblyView'

const Main = () => {
  return ( //
      <main>
        <Switch>
          <Route path='/dashboard' component={Splash}/>
          <Route path='/disasm' render={getDisassemblyView}/>
          <Route component={Splash}/>
        </Switch>
      </main>)
}
const getDisassemblyView = (props) => {

  return (
    <DisassemblyView {...props} />
  )
}
export default Main
