// Upload a file
export default function uploadFileToDisassemble(file) {
  console.log(`uploading ${file.name}...`)
  let formData = new FormData();
  formData.append('fileToDisassemble', file);

  return fetch("http://localhost:5000/disassemble-file", {
    method: "POST",
    body: formData
  }).then((response) => {

    return response.json()
  }).catch((error) => {
    // TODO fixme
    alert("Got error from server");
  })

}
