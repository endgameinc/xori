import {createMuiTheme} from '@material-ui/core/styles';

export default createMuiTheme({
  palette: {
    type: 'dark',
    text: '#B5BBC7',
    primary: {
      main: '#00AAE1',
      dark: '#143C8C',
      contrastText: '#f0f',
    },
    secondary: {
      main: '#64B42D',
      dark: '#008732',
      contrastText: '#f0f',
    },
    error: {
      main: '#BD0043',
      contrastText: '#fff',
    },
    divider: 'rgba(18, 18, 18, 0.2)',
    background: {
      paper: '#2C2A35',
      default: "#ff0000"
    },
  },
});
