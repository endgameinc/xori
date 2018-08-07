import React, {Component} from 'react';
import {MuiThemeProvider} from '@material-ui/core/styles';
import theme from './theme.js'
import Header from './header'
import Main from './main'
import './app.css'
class App extends Component {
  render() {
    return ( //
        <div className="App">
          <MuiThemeProvider theme={theme}>
            <Header></Header>
            <Main></Main>
          </MuiThemeProvider>
        </div>);
  }
}

export default App;
