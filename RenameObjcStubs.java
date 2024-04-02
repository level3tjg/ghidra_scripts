//Rename _objc_msgSend stubs
//@author level3tjg
//@category iOS

import ghidra.app.script.GhidraScript;
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
    	
    	MemoryBlock stubsBlock = getMemoryBlock("__objc_stubs");
    	
    	for (Function func : functionManager.getFunctions(false)) {
    		Address entryPoint = func.getEntryPoint();
    		long offset = entryPoint.getOffset();
    		
    		if (offset < stubsBlock.getStart().getOffset()) break;
    		if (offset > stubsBlock.getStart().getOffset() + stubsBlock.getSize()) continue;
    		
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
