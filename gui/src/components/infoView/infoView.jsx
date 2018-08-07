import React, {Component} from 'react';
import Card from '@material-ui/core/Card';
import CardContent from '@material-ui/core/CardContent';
import Table from '@material-ui/core/Table';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import TableHead from '@material-ui/core/TableHead';
import TableRow from '@material-ui/core/TableRow';
import Typography from '@material-ui/core/Typography';
import ExpansionPanel from '@material-ui/core/ExpansionPanel';
import ExpansionPanelSummary from '@material-ui/core/ExpansionPanelSummary';
import ExpansionPanelDetails from '@material-ui/core/ExpansionPanelDetails';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';

import './infoView.css';

class InfoView extends Component {
  constructor(props) {
    super(props)
    if (props.info === undefined) {
      console.error("InfoView not passed required prop: info");
    }
  }
  render() {
    var imports = <li>None</li>
    var sections = <li>None</li>
    if (this.props.info.import_table !== undefined && this.props.info.import_table !== null) {
      imports = Object.entries(this.props.info.import_table).map((entry, index) => {
        var importvalue = entry[1]
        var ifunctions = Object.entries(importvalue.import_address_list).map((ientry, iindex) => {
          var ifunc = ientry[1]
          return ( //
              <ListItem key={ifunc.func_name + Math.random().toString(16)} divider={true}>
                <ListItemText primary={ifunc.func_name}/>
              </ListItem>)
        })
        return ( //
            <ExpansionPanel key = {importvalue.name + Math.random().toString(16)} className="import">
              <ExpansionPanelSummary>
                <Typography>{importvalue.name}</Typography>
              </ExpansionPanelSummary>
              <ExpansionPanelDetails>
                <List>
                  {ifunctions}
                </List>
              </ExpansionPanelDetails>
            </ExpansionPanel>)
      })
    }

    if (this.props.info.section_table !== undefined && this.props.info.section_table !== null) {
      sections = Object.entries(this.props.info.section_table).map((entry, index) => {
        var section = entry[1]
        if (section.virtual_size !== undefined) {
          var vsize = section.virtual_size.toString(16)
        }
        if (section.virtual_address !== undefined) {
          var vaddr = section.virtual_address.toString(16)
        }
        return ( //
            <TableRow key={section.name + Math.random().toString(16)}>
              <TableCell>{section.name}</TableCell>
              <TableCell>0x{vaddr}</TableCell>
              <TableCell>0x{vsize}</TableCell>
              <TableCell>0x{section.characteristics.toString(16)}</TableCell>
            </TableRow>)
      })
    }
    return ( //
        <div className="InfoView" ref="scrolling_div">
          <div className="InfoContent">
            <Card className="card">
              <CardContent>
                <Typography variant="title">
                  File Information
                </Typography>
                <ul className="InfoView">
                  <li>
                    <span className="label">File Name</span>{this.props.info.filename}
                  </li>
                  <li>
                    <span className="label">Binary Type</span>{this.props.info.binary_type}
                  </li>
                  <li>
                    <span className="label">Mode</span>{this.props.info.mode}
                  </li>
                  <li>
                    <span className="label">Image Base</span>0x{this.props.info.image_base.toString(16)}
                  </li>
                  <li>
                    <span className="label">Image Size</span>0x{this.props.info.size_of_image.toString(16)}
                  </li>
                  <li>
                    <span className="label">EntryPoint</span>0x{this.props.info.address_of_entry_point.toString(16)}
                  </li>
                </ul>
              </CardContent>
            </Card>
            <Card className="card">
              <CardContent>
                <Typography variant="headline">Imports</Typography>
                <br/> {imports}
              </CardContent>
            </Card>
            <Card className="card">
              <CardContent>
                <Typography variant="title">
                  Section Table
                </Typography>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Virtual Address</TableCell>
                      <TableCell>Virtual Size</TableCell>
                      <TableCell>Characteristics</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {sections}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

          </div>
        </div>);
  }
}

export default InfoView;
