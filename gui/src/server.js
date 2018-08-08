// Server to connect to xori engine
var express = require('express')
var app = express()
var multer = require('multer')
const path = require('path')
var fs = require('fs');
var mv = require('mv');
var chokidar = require('chokidar');
const md5File = require('md5-file')

const {
  spawn
} = require('child_process');

const dynamic_storage_path = path.normalize(__dirname + "/../dynamic")
const xori_executable_path = path.normalize("./target/release/xori")
const xori_config_path = path.normalize("./xori.json")
console.log("XORI Executable path: " + xori_executable_path);
console.log("Dynamic storage path: " + dynamic_storage_path);

var upload = multer({
  dest: dynamic_storage_path
});

//Allow cross origin request from anything FIXME
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});


// respond with "hello world" when a GET request is made to the homepage
app.post('/disassemble-file', upload.single('fileToDisassemble'), function(req, res) {
  console.log(req.body);
  console.log(req.file)
  const md5_hash = md5File.sync(req.file.path);
  const report_path = path.normalize(dynamic_storage_path + "/reports/")
  // Create reports folder if it doesn't already exits
  if (!fs.existsSync(report_path)) {
    fs.mkdirSync(report_path);
  }
  const output_path = path.normalize(report_path + md5_hash)
  console.log("md5_hash: ", md5_hash)
  console.log("output_path: ", output_path)

  // Make folder to put files in, needed b/c xori makes it's own uuids and we can't correlate them.
  if (!fs.existsSync(output_path)) {
    fs.mkdirSync(output_path);
  }

  // Dispatch job to Xori sub processa
  const xori_instance = spawn(xori_executable_path, ["-f", req.file.path, "--config", xori_config_path, "--output", output_path], {cwd: '../'})
  // Setup event handlers to listen to subproces events
  xori_instance.stdout.on('data', (data) => {
  })
  xori_instance.stderr.on('data', (data) => {
    console.log("Xori Error output: ", data.toString());
  })
  xori_instance.on("close", (code) => {
    console.log("Xori exited with code" + code);
  })
  // Setup event handler to watch for file changes to pickup files when Xori drops to disk.
  var watcher = chokidar.watch(output_path, {
    ignored: /(^|[\/\\])\../,
    persistent: true
  });
  var didReceiveDisasm = false,
    disasmObject = undefined,
    didReceiveFunctions = false,
    functionsObject = undefined,
    didReceiveHeader = false,
    headerObject = undefined,
    didXoriExit = false;

  watcher
    .on('add', (new_file_path) => {
      console.log(`File added: ${new_file_path}`);
      if (new_file_path.includes("disasm")) {
        console.log("Received new disassembly")
        disasmObject = JSON.parse(fs.readFileSync(new_file_path));
        didReceiveDisasm = true;
      }
      if (new_file_path.includes("functions")) {
        console.log("Received new functions")
        functionsObject = JSON.parse(fs.readFileSync(new_file_path));
        didReceiveFunctions = true;
      }
      if (new_file_path.includes("header")) {
        console.log("Received new header")
        headerObject = JSON.parse(fs.readFileSync(new_file_path));
        didReceiveHeader = true;
      }
      if (didReceiveDisasm && didReceiveFunctions && didReceiveHeader) {
        // build response
        console.log("Received all required files to send response");
        const response = {
          "disasm": disasmObject,
          "functions": functionsObject,
          "info": headerObject
        }
        // send created response
        res.json(response);
        // Cleanup the job
        // unregister file change event handler


        watcher.close()


        // move job file into created job folder reports/md5hash/md5hash_uuid
        var job_destination_path = path.normalize(output_path + "/" + md5_hash + "_" + req.file.filename)
        mv(req.file.path, job_destination_path, {
          mkdirp: true
        }, function(error) {
          if (error) {
            console.log("error:", error)
          }
        })
      }
    });
})

app.listen(process.env.port || 5000, () => {
  console.log(`Xori request server listening on ${process.env.port || 5000}`)
})
