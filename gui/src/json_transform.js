
/**
 * Takes a disassembly json and a function json (the output of running xori) and converts it to a tree like structure, like so:
 *
 * {
 *    root: the entrypoint block, containing start and end addresses, as well as instructions, and jumps
 *    blocks: an object containing all blocks in the json files, with the key being the start address of the block
 * }
 *
 */

export default function(instructionDescriptors , functionDescriptors , selectedFunction) {
  const instructionAddresses = Object.keys(instructionDescriptors).sort()
  const xrefs = collectxrefs(functionDescriptors);

  var functionBlocks = {};
  functionDescriptors.forEach(function (func) {
    if (func.mem_type === "Image")
    {
      functionBlocks[func.address] = createBlockFromFunctionDescriptor(func);
    }
  });

  return functionBlocks;

  function collectxrefs(functionDescriptors)
  {
    const xrefs = {}

    functionDescriptors.forEach(function (func) {
      func.xrefs.forEach(function (xref) {

          xrefs[xref] = func.address
      });
    });
    return xrefs
  }

  function createBlockFromFunctionDescriptor(functionDescriptor) {
    var blocks = {};
    /* BlockType */
    const blockStart = 0
    const blockBegin = 1
    const blockEnd = 2
    const blockReturn = 3
    const blockBoth = 4

    var blockSeparators = {}
    /* Insert the first address */
    blockSeparators[functionDescriptor.address] = [blockStart, 0, 0]

   /* Get all the returns */
    if (functionDescriptor.returns.length > 0) {
      for (var retindex in functionDescriptor.returns) {
        let ret = functionDescriptor.returns[retindex]
        if (ret !== 0) {
          if (ret in blockSeparators) {
            if (blockSeparators[ret][0] === blockStart || blockSeparators[ret][0] === blockBegin) {
              blockSeparators[ret][0] = blockBoth
            }
          } else {
            blockSeparators[ret] = [blockReturn, 0, 0]
          }
        }
      }
    }

    /* Get all the Jumps */
    if (Object.keys(functionDescriptor.jumps).length > 0) {
      for (const [key, jump] of Object.entries(functionDescriptor.jumps)) {

        if (key in blockSeparators)
        {
          if (blockSeparators[key][0] === blockStart || blockSeparators[key][0] === blockBegin) {
            blockSeparators[key] = [blockBoth, jump.left, jump.right]
          } else if (blockSeparators[key][0] === blockEnd)
          {
            blockSeparators[key][2] = jump.right
          }
        } else {

          blockSeparators[key] = [blockEnd, jump.left, jump.right]
        }

        if (jump.left !== 0) {
          if (jump.left in blockSeparators) {
            if (blockSeparators[jump.left][0] === blockEnd || blockSeparators[jump.left][0] === blockReturn) {
              blockSeparators[jump.left][0] = blockBoth
            }
          } else {
            blockSeparators[jump.left] = [blockBegin, 0, 0]
          }
        }
        /* End jump left */
        if (jump.right !== 0) {
          if (jump.right in blockSeparators) {
            if (blockSeparators[jump.right][0] === blockEnd || blockSeparators[jump.right][0] === blockReturn) {
              blockSeparators[jump.right][0] = blockBoth
            }
          } else {
            blockSeparators[jump.right] = [blockBegin, 0, 0]

            const indexOfJumpRight = instructionAddresses.indexOf(jump.right.toString())
            if (indexOfJumpRight - 1 > 0) {
              const previousInstr = parseInt(instructionAddresses[indexOfJumpRight - 1], 10)

              if (previousInstr in blockSeparators) {
                if (blockSeparators[previousInstr][0] === blockStart || blockSeparators[previousInstr][0] === blockBegin) {
                  blockSeparators[previousInstr][0] = blockBoth
                  blockSeparators[previousInstr][1] = jump.right
                }
              } else {
                blockSeparators[previousInstr] = [blockEnd, jump.right, 0]
              }
            }

          }
        }
        /* End jump right */
      }
    }

    const blockSeparatorKeys = Object.keys(blockSeparators).sort()
    let index = 0
    while (index < blockSeparatorKeys.length) {
      if (blockSeparators[blockSeparatorKeys[index]][0] === blockBoth) {
        const jumps = []
        let start = parseInt(blockSeparatorKeys[index],10)
        let end = parseInt(blockSeparatorKeys[index],10)
        let left = parseInt(blockSeparators[blockSeparatorKeys[index]][1],10)
        let right = parseInt(blockSeparators[blockSeparatorKeys[index]][2],10)
        let name = undefined;
        if (left !== 0) {
          const blah = {
            start: left,
            type: "left",
            index: 0
          }
          jumps.push(blah)
        }
        if (right !== 0) {
          const blah = {
            start: right,
            type: "right",
            index: 0
          }
          jumps.push(blah)
        }
        const instructions = instructionsInRange(functionDescriptor.address, parseInt(start, 10), parseInt(end, 10))
        const block = {
          start,
          end,
          instructions,
          jumps,
          name
        }
        block.id = start
        blocks[start] = block

        index = index + 1
        continue
      } else if (blockSeparators[blockSeparatorKeys[index]][0] === blockBegin || blockSeparators[blockSeparatorKeys[index]][0] === blockStart) {
        const jumps = []
        let start = parseInt(blockSeparatorKeys[index],10)
        let name = undefined;
        if (index + 1 >= blockSeparatorKeys.length) {
          let end = parseInt(blockSeparatorKeys[index],10)
          const instructions = instructionsInRange(functionDescriptor.address, parseInt(start, 10), parseInt(end, 10))
          const block = {
            start,
            end,
            instructions,
            jumps,
            name
          }
          block.id = start
          blocks[start] = block
          index = index + 1
          continue
        }
        if (blockSeparators[blockSeparatorKeys[index + 1]][0] === blockEnd || blockSeparators[blockSeparatorKeys[index + 1]][0] === blockReturn) {
          let end = parseInt(blockSeparatorKeys[index + 1],10)
          let left = parseInt(blockSeparators[end][1],10)
          let right = parseInt(blockSeparators[end][2],10)
          if (left !== 0) {
            const blah = {
              start: left,
              type: "left",
              index: 0
            }
            jumps.push(blah)
          }
          if (right !== 0) {
            const blah = {
              start: right,
              type: "right",
              index: 0
            }
            jumps.push(blah)
          }
          const instructions = instructionsInRange(functionDescriptor.address, parseInt(start, 10), parseInt(end, 10))
          const block = {
            start,
            end,
            instructions,
            jumps,
            name
          }
          block.id = start
          blocks[start] = block

        } else if (blockSeparators[blockSeparatorKeys[index + 1]][0] === blockBoth || blockSeparators[blockSeparatorKeys[index + 1]][0] === blockStart){
          index = index + 1
          continue
        }

        index = index + 2
        continue
      } else if (blockSeparators[blockSeparatorKeys[index]][0] === blockEnd) {
        index = index + 1
        continue
      }
      index = index + 1
    }
    /* End While Loop */

    /* Get root block */
    if (functionDescriptor.address in blocks)
    {
      if (functionDescriptor.name === undefined || functionDescriptor.name === "")
      {
        if (blocks[functionDescriptor.address].hasOwnProperty('start'))
        {
          blocks[functionDescriptor.address].name = `sub_${blocks[functionDescriptor.address].start.toString(16)}`
        }
      } else if (blocks[functionDescriptor.address] !== undefined)
      {
        blocks[functionDescriptor.address].name = functionDescriptor.name;
      }
    }
    let root = blocks[functionDescriptor.address]


    return {root, blocks}
  }

  function instructionsInRange(owningFunction, startAddress, endAddress) {
    // returns an array of instructions from a start address to an end address inclusive
    const instructions = []
    let index = startAddress
    while (index <= endAddress) {

      let currentInstruction = instructionDescriptors[index]
      if (currentInstruction === undefined) {
        // sometimes we may not have an instruction, so just increment and look on
        index++
        continue;
      }
      currentInstruction.owned = owningFunction;
      if (index in xrefs)
      {
        currentInstruction.destination = xrefs[index];
      }
      instructions.push(currentInstruction)
      index = index + currentInstruction.instr.size
    }

    return instructions
  }
}
