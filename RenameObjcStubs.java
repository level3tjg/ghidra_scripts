//Rename _objc_msgSend stubs
//@author level3tjg
//@category iOS

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class RenameObjcStubs extends GhidraScript {

    public void run() throws Exception {
    	FunctionManager functionManager = currentProgram.getFunctionManager();
    	String format = currentProgram.getExecutableFormat();
    	
    	if (!format.contains("Mach-O"))
    		throw new Exception("Executable is not Mach-O");
    	
    	for (MemoryBlock block : getMemoryBlocks())
    		if (block.getName().contains("__bss") && !block.isInitialized())
    			currentProgram.getMemory().convertToInitialized(block, (byte)0);
    	
    	MemoryByteProvider provider = new MemoryByteProvider(currentProgram.getMemory(), currentProgram.getMinAddress());
    	MachHeader header = new MachHeader(provider).parse();
    	Section stubsSection = header.getSection("__TEXT", "__objc_stubs");
    	
    	for (Function func : functionManager.getFunctions(false)) {
    		Address entryPoint = func.getEntryPoint();
    		long offset = entryPoint.getOffset();
    		
    		if (offset < stubsSection.getAddress()) break;
    		if (offset > stubsSection.getAddress() + stubsSection.getSize()) continue;
    		
    		CodeUnit unit = currentProgram.getListing().getCodeUnitAfter(entryPoint);
    		Reference[] references = unit.getOperandReferences(1);
    		
    		if (references.length == 0) {
    			printerr(String.format("Operand at %s has no reference", unit.getAddress().toString(true)));
    			continue;
    		}
    		
    		Data selectorData = currentProgram.getListing().getDataAt(references[0].getToAddress());
    		Object selectorValue = selectorData.getValue();
    		if (selectorValue instanceof Address)
    			selectorValue = currentProgram.getListing().getDataAt((Address)selectorValue).getValue();
    		String selectorString = selectorValue.toString();
    		
    		String funcName = func.getName();
    		String stubName = String.format("_objc_msgSend$%s", selectorString);
    		func.setName(stubName, SourceType.USER_DEFINED);
    		
    		println(String.format("Renamed %s to %s", funcName, stubName));
    	}
    }

}
