import React from 'react'
import {Link} from 'react-router-dom'
import logo from './logo.png';

const Header = ()=>{
  return(//
    <header className="App-header">
      <img src={logo} className="App-logo" alt="logo"/>
      <nav>
        <ul>
          <li>
            <Link to='/dashboard'>DASHBOARD</Link>
          </li>
          <li>
            <Link to='/disass'>DISASM</Link>
          </li>
        </ul>
      </nav>
    </header>
  )
}

export default Header
