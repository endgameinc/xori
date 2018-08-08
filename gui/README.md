# Xori GUI

Install:

- We use yarn, an alternative to npm.
- You must build xori before running the gui

### First Run

From the gui folder run:

      yarn install
      yarn start

In another terminal from the same folder run:

      node src/server.js

### Subsequent Runs
On subsequent runs you only need to:

    yarn start & node src/server.js

### Development:

- Every time you pull new code run through first run.
- Your changes to the ui will hotload
- Use nodemon to hotload your changes to the API server

#### Known issues:

- We use chokidar for watching file events on the API server, it will crash sometimes when the watcher isn't ready. [Their Issue Here](https://github.com/paulmillr/chokidar/issues/612)

- The Control Flow Graph doesn't have back links

- Basic Blocks are inserted into the control flow graph when a reference does not exist in a function. 

### Browser Testing:

- Chrome 68   , All features work, Development Browser
- Firefox 61  , All features work, Scrollbar un-styled
- Safari 11   , All features work, The font is a bit wonky
- Edge 41     , All features work, The font is wonky, the scroll bar is un-styled, the HTML embedded in the SVG graph sometimes sizes itself too large, the gradients look off.
- Explorer 11 , It crashes, we use a lot of es5/es6
