import React, {Component} from 'react';
import './splash.css';
import Dropzone from 'react-dropzone'
import Settings from '../settings/settings'
import {Redirect} from 'react-router-dom'
class Splash extends Component {
  constructor() {
    super();
    this.state = {
      files: []
    }
  }
  onDrop(files) {
    console.log("dropped files: ", files);
    this.setState({files});
  }
  render() {
    return ( //
        <div className="Splash">
          {
            this.state.files.length > 0
              ? <div>have files
                  <span>{JSON.stringify(this.state.files)}
                  </span>
                  <Redirect to={{
                      pathname: '/disasm',
                      state: {
                        files: this.state.files
                      }
                    }}/>
                </div>
              : <div>no files</div>
          }
          <Dropzone className="fileDropZone" onDrop={this.onDrop.bind(this)}>
            <h2>Drop a file here</h2>
          </Dropzone>
          <Settings/>
          <div className="credits">
            <div className="bottomLeft"></div>
            <div className="centerCallout">
              <p>Maintainers:
                <a href="https://twitter.com/malwareunicorn" className="peoplelinks">
                  @malwareunicorn</a>,&nbsp;
                <a href="https://twitter.com/rseymour" className="peoplelinks">@rseymour</a>
              </p>
              <p>Contributors:
                <a className="peoplelinks" href="https://twitter.com/_lucienbrule">@_lucienbrule</a>
                (UI),
                <a className="peoplelinks" href="CONTRIBUTING.md">
                  &nbsp; your name here!?
                </a>
              </p>
            </div>
            <div className="bottomRight">
              <p>VERSION @0.1.0</p>
              <p>COPYRIGHT &lt; 2018 &gt;</p>
              <p>
                <a className="peoplelinks" href="https://www.gnu.org/licenses/agpl-3.0">LICENSE (GNU AGPL v3)</a>
              </p>
              <p>
                <a className="peoplelinks" href="https://gitlab.com/">REPOSITORY</a>
              </p>

            </div>
          </div>
        </div>);
  }
}

export default Splash;
