/*
 Converts object of this structure:

 {
   root: object,
   blocks: object containing all blocks where their key is the starting address
 }

 to a D3 supported structure like this:
 {
    nodes: array of the original objects with ids added,
    links: array of { source: id, target: id }
  }
*/



export default function(data) {
  const nodes = []
  const links = []
  for (let [ address, block ] of Object.entries(data.blocks)) {
    block.id = address
    block.group = 1
    for (let jump of block.jumps) {
      links.push({ source: block.id, target: jump.start, type:jump.type})
    }
    nodes.push(block)
  }
  return {
    nodes,
    links
   }
}
