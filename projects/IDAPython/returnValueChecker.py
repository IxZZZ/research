# Information about IDA Pro's basic block feature and how to use the APIs
# was taken from http://moritzraabe.de/2017/01/15/ida-pro-anti-disassembly-basic-blocks-and-idapython/
# Credits go to him for documenting it in a clear manner.


def findReturnBlockOffset(flowChart):
    returnBlockOffset = 0
    while (returnBlockOffset < flowChart.size):
        if flowChart[returnBlockOffset].type == idaapi.fcb_ret: # Taken from https://www.hex-rays.com/products/ida/support/sdkdoc/gdl_8hpp.html#afa6fb2b53981d849d63273abbb1624bd 
                                                                # which shows that block type 2 is fbc_ret, or a return block.
            break
        else:
            returnBlockOffset += 1
            
    if (returnBlockOffset > flowChart.size):
        print("Something is seriously wrong! Couldn't find the basic block that returns execution to the caller!")
        return -1
    else:
        print("Found return block at offset %d in the flowChart array!" % returnBlockOffset)
        return returnBlockOffset

def printFlowTable(flowTable):
    for i in flowTable:
        print("%d, %x" %(i[0], i[1]))
        for entry in i[3]:
            print(" [*] Branch option: %x" % entry)

def printNumFunctionBasicBlocks(flowChart):
    # And for reference let's obtain the function name using get_func_name(), then print this out along with the number of basic blocks in the function.
    print("%s has %d basic blocks!" %(idaapi.get_func_name(here()), flowChart.size))


# Build out the flow table in the variable flowTable, given a function flow chart.
def buildFlowTable(flowChart):
    flowTable = []

    entryNumber = 0
    while (entryNumber < flowChart.size):
        successorArray = flowChart[entryNumber].succs()

        nextEntryArray = [i.startEA for i in successorArray]
        flowTable.append([entryNumber, flowChart[entryNumber].startEA, flowChart[entryNumber].endEA, nextEntryArray])
        entryNumber += 1
    return flowTable

def enumerateBlocksThatJumpDirectlyToReturnBlock(flowTable, returnBlockStartEA):
    blocksThatHitReturnBlockDirectly = []
    for entry in flowTable:
        blocksThatHitReturnBlockDirectly.extend(
            [entry[0], entry[1], entry[2]]
            for nextBlock in entry[3]
            if nextBlock == returnBlockStartEA
        )
    return blocksThatHitReturnBlockDirectly

def doesReturnBlockModifyRAX(returnBlockStartEA, returnEndEA):
    currentEA = returnBlockStartEA
    while currentEA < returnEndEA:
        if (idc.print_insn_mnem(currentEA) == "mov"):
            if idc.print_operand(currentEA, 0) in ["rax", "eax"]:
                return True
        elif (idc.print_insn_mnem(currentEA) == "xor"):
            if idc.print_operand(currentEA, 0) in ["rax", "eax"]:
                return True
        currentEA = idc.next_head(currentEA)
    return False

def printBanner():
    print("")
    print("------------------------------------------------------------------")
    print("VS-Labs Research Team Data Pointer Leaker Detector - Lite Edition")
    print("Author: Grant Willcox (@tekwizz123)")
    print("------------------------------------------------------------------")

def findPotentialDataLeaks(blocksThatHitReturnBlockDirectly):
    for block in blocksThatHitReturnBlockDirectly:
        blockStartEA = block[1]
        blockEndEA = block[2]
        currentEA = blockStartEA
        flagHitMovEAX = False

            # Uncomment the following line to see the start and end positions of each of the blocks in the array blocksThatHitReturnBlockDirectly
            #print("Block Start: %x  Block End: %x" %(blockStartEA, blockEndEA))
        while (currentEA < blockEndEA):
            if (
                (idc.print_insn_mnem(currentEA) == "mov")
                and (idc.print_operand(currentEA, 0) == "rax")
                and (idc.get_operand_type(currentEA, 1) == idaapi.o_mem)
                and flagHitMovEAX != True
            ):
                print("Potentially leaking %s at %x" %(idc.print_operand(currentEA, 1), currentEA) )
                flagHitMovEAX = True
                currentEA = idc.next_head(currentEA) # Need this as we don't want to repeat the same result we just detected.
                while (currentEA < blockEndEA):
                    if (
                        idc.print_insn_mnem(currentEA) != "test"
                    ) and idc.print_operand(currentEA, 0) in ["rax", "eax"]:
                        if (idc.get_operand_type(currentEA, 1) != idaapi.o_mem):
                            print(" [!] Looks like leak wasn't true. RAX/EAX gets clobbered at %x" %(currentEA))
                        else:
                            print(" [*] Interesting, looks like we may have had RAX overwritten with another leak. Updating...")
                            print("Potentially leaking %s at %x" %(idc.print_operand(currentEA, 1), currentEA) )
                    currentEA = idc.next_head(currentEA)
            currentEA = idc.next_head(currentEA)

def main():
    # Print banner
    printBanner()

    # First let's get the function object for the current function.
    functionObject = idaapi.get_func(here())
    try:
        if functionObject is None:
            print("This is not a function! Exiting!")
            return -1
    except:
        print("Looks like this is a function. Continuing...")

    # Now let's get its flowchart.
    flowChart = idaapi.FlowChart(functionObject)
    try:
        if flowChart is None:
            print("Could not build a flow chart! Exiting!")
            return -1
    except:
        print("Exception occurred when trying to find the flowchart! Exiting!")
        return -1

    # Print out info about the number of basic blocks
    # found in the current function. Comment this out
    # if you are not interested in seeing this in the output.
    printNumFunctionBasicBlocks(flowChart)

    # Locate which basic block within the flow chart array is the one that is the basic block containing the ret/retn instruction.
    returnBlockOffset = findReturnBlockOffset(flowChart)
    if (returnBlockOffset == -1):
        return -1

    # Get the address in virtual memory where the basic block containing the ret/retn instruction is located.
    returnBlockStartEA = flowChart[returnBlockOffset].startEA

    # Build the flow table from the flow chart that we currently possess.
    flowTable = buildFlowTable(flowChart)

    # Uncomment this to print out the full flow table.
    #printFlowTable(flowTable)

    # Enumerate basic blocks that jump directly to the block containing the ret/retn address, and save them into an array.
    blocksThatHitReturnBlockDirectly = enumerateBlocksThatJumpDirectlyToReturnBlock(flowTable, returnBlockStartEA)

    # Verify that the return block doesn't have anything that modifies RAX, as the script currently doesn't support such functions.
    flagReturnAddressModifiesRAX = doesReturnBlockModifyRAX(returnBlockStartEA, flowChart[returnBlockOffset].endEA)

    if (flagReturnAddressModifiesRAX == False):
       findPotentialDataLeaks(blocksThatHitReturnBlockDirectly)
    else:
        print("Return block modifies EAX. This is currently not something that this function can rectify. Manual analysis recommended.")
        return -1
            
# Call main()
main()
