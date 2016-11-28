# Pykd script to help debugging Adobe FlashPlayer on Firefox
# ryujin and ronin @ Offensive Security
# Please in Firefox change the following configuration in about:config
# dom.ipc.plugins.hangUITimeoutSecs = 0
# dom.ipc.plugins.contentTimeoutSecs = 0
# dom.ipc.plugins.processLaunchTimeoutSecs = 0
# dom.ipc.plugins.timeoutSecs = 0
# dom.ipc.plugins.unloadTimeoutSecs = 0 
# In this way we won't trigger the plugin-hang-ui
#
# The script works on Firefox only for now and was tested on Flash >= 17.0.0.188 32bit
# Requirements: pykd >= 0.3

import pykd
import fnmatch, struct, sys, time, pickle, tempfile, os
from optparse import OptionParser

func_sigs = {'setNative':		 	'8B 41 08 80 78 38 00 8b 44 24 04 74 10',
			 'setJit':			 	'8B 4C 24 08 56 8B 74 24 08 8B 46 30 25',
			 'setInterp':		 	'33 c0 38 44 24 0c 53 55 0f 95 c0',
			 'getMethodName':	 	'8B 41 10 A8 01 74 13 83 E0 FE 74 0C 8B',
			 'FixedMalloc::OutOfLineAlloc': '81 FA F0 07 00 00',
			 'FixedMalloc::LargeAlloc': 	'33 c9 05 00 10 00 00',
			 'GCAlloc::Alloc':			 	'8B 46 20 29 81 AC 01 00 00',
			 }
			 
fixedmalloc_funcs_sigs = {
	'cmp esi,7F0h': '81 FE F0 07 00 00', # cmp esi, 7F0h
	'cmp eax,7F0h': '3D F0 07 00 00',    # cmp eax, 7F0h
	'cmp ebp,7F0h': '81 FD F0 07 00 00', # cmp ebp, 7F0h
	'cmp edi,7F0h': '81 FF F0 07 00 00', # cmp edi, 7F0h
	'cmp edx,7F0h': '81 FA F0 07 00 00', # cmp edx, 7F0h # OutOfLineAlloc sig.
	'cmp ebx,7F0h': '81 fb f0 07 00 00', # cmp ebx, 7f0h # one in 18.0.0.360
	'cmp ecx,7F0h': '81 f9 f0 07 00 00', # cmp ecx, 7F0h # never found this sig.
			 }
			 
# From AVM source code:
# FixedMalloc::kSizeClassIndex[kMaxSizeClassIndex]
# kSizeClassIndex[] is an array that lets us quickly determine the allocator
# to use for a given size, without division.  A given allocation is rounded
# up to the nearest multiple of 8, then downshifted 3 bits, and the index
# tells us which allocator to use.(A special case is made for <= 4 bytes on
# 32-bit systems in FindAllocatorForSize to keep the table small.) 			 
kSizeClassIndex = [
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 17, 18, 18, 19, 19, 20, 21, 22, 23, 24, 24, 25, 26, 26,
	27, 27, 28, 28, 28, 29, 29, 29, 30, 30, 30, 31, 31, 31, 31, 32,
	32, 32, 32, 33, 33, 33, 33, 33, 33, 34, 34, 34, 34, 34, 34, 34,
	35, 35, 35, 35, 35, 35, 35, 35, 35, 36, 36, 36, 36, 36, 36, 36,
	36, 36, 36, 36, 36, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37, 37,
	37, 37, 37, 37, 37, 37, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38,
	38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38,
	39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39,
	39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39,
	39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 40, 40, 40, 40, 40, 40,
	40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
	40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
	40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
	40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
	40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40]
			 
func_sigs_ends = {'FixedMallocEnd':	'51 8B 44', 'GCAllocEnd': '56 57 8b'}			 
func_addr = {'setNative':'','setJit':'','setInterp':'','getMethodName':''}

NPS = {'filename': 'NPSWF32', 'size': 0x0, 'base_addr': 0x0, 'end_addr': 0x0, 
	    'count': 0x0, 'HOOK_JIT': False, 
	    'HOOK_NATIVE': False, 'HOOK_INTERP': False,
	  }
GBP = {}
GBP['HOOK_JIT'] = False
GBP['HOOK_NATIVE'] = False
GBP['HOOK_INTERP'] = False
GBP["START_ALLOC_MONITOR"] = False
GBP["FixedMallocBPs"] = {}
GBP["GCAllocBPs"] = {}
GBP["AllocHistory"] = {}

DEBUG_BREAK_READ    = 0x00000001
DEBUG_BREAK_WRITE   = 0x00000002
DEBUG_BREAK_EXECUTE = 0x00000004

class ExceptionHandler(pykd.eventHandler):
	"""Custom Exception Handler Class"""
	def __init__(self):
		pykd.eventHandler.__init__(self)
		self.count = 0
		self.exception_occurred = False
		self.interesting_exceptions = {0x80000001: "GUARD_PAGE_VIOLATION",
									   0x80000005: "BUFFER_OVERFLOW",
									   0xC0000005: "ACCESS_VIOLATION",
									   0xC000001D: "ILLEGAL_INSTRUCTION",
									   0xC0000144: "UNHANDLED_EXCEPTION",
									   0xC0000409: "STACK_BUFFER_OVERRUN",
									   0xC0000602: "UNKNOWN_EXCEPTION",
									   0xC00000FD: "STACK_OVERFLOW",
									   0xC000009D: "PRIVILEGED_INSTRUCTION",
									   0x80000003: "BREAK_INSTRUCTION"}
		self.exception_info = None

	def exceptionOccurred(self):
		return self.exception_occurred

	def getExceptionInfo(self):
		return self.exception_info

	def onException(self, exceptInfo):
		if not exceptInfo.firstChance:
			self.exception_occurred = True
			print "[!] Exception caught!"
			return pykd.eventResult.Break
		return pykd.eventResult.NoChange
		
class ModuleLoadHandler(pykd.eventHandler):
	"""Track load/unload module implementation"""
	def __init__(self, moduleMask):
		pykd.eventHandler.__init__(self)
		self.moduleMask = moduleMask.lower()
		self.wasLoad = 0
		self.wasUnload = False

	def onLoadModule(self, modBase, name):
		"""Load module handler"""
		global NPS
		# look for NPSWF32*
		if ( fnmatch.fnmatch(name.lower()[0:7], self.moduleMask) ):
			self.wasLoad = modBase
			print "[+] LOADED MODULE: %s at 0x%x" % (name, modBase)
			NPS['count'] += 1
			NPS['base_addr'] = modBase
			try:
				NPS['version'] = [int(x) for x in name.split("_")[1:]]
				if IsheapIsolVersion():
					NPS["FixedAllocSafeSize"] = 0x28
					NPS["m_allocs_offset"] = 0x8
				else:
					NPS["FixedAllocSafeSize"] = 0x24
					NPS["m_allocs_offset"] = 0x4				
			except Exception, e:
				print "[!] Error while extracting DLL version from %s" %\
					name
				print "[!] " + str(e)
		return pykd.executionStatus.Break

def IsheapIsolVersion():
	"""Check if Flash version has heap isolation features"""
	if NPS["version"][0] > 20:
		return True
	elif NPS["version"][0] == 20 and NPS["version"][-1] >= 235:
		return True
	else:
		return False
		
def calcJmp(from_addr, to_addr):
	"""Calculate Near Jmp Offset and assemble the opcode for the hooks"""
	if to_addr > from_addr:
		# DST-(SRC+5)
		offset = to_addr - (from_addr+0x5)
		jmp = "\xE9" + struct.pack("L", offset)
	else:
		# NOT((SRC+5) - DST - 1)
		offset = (~((from_addr + 0x5) - to_addr - 0x1)) & 0xFFFFFFFF 
		jmp = "\xE9" + struct.pack("L", offset)
	return jmp
		
def writeHookJit(hook_address):
	"""Write the code for the setJit hook"""
	# 0:  60              pusha							# save registers
	# 1:  89 f9           mov  ecx,edi					# edi = MethodInfo 
	# 3:  30 d2           xor  dl,dl
	# 5:  b8 XX XX XX XX  mov  eax,0xXXXXXXXX			# load getMethodName 
	#					 								# address
	# a:  ff d0           call eax						# call getMethodName
	# c:  61              popa							# restore registers
	# d:  8b 4c 24 08     mov ecx,dword ptr [esp+0x8]	# first instruction
	#					 								# of setJit
	absaddr = setJit = ""
	for b in struct.pack("<L",(func_addr['getMethodName'])):
		absaddr += hex(struct.unpack("B",b)[0]).split("0x")[1] + " "
	# plus 4 so we dont hit the BP again		
	jmp = calcJmp(hook_address+0x11, func_addr['setJit']+0x4) 
	for b in jmp:
		setJit += hex(ord(b)).split("0x")[1] + " "
	xbytes = "60 89 F9 30 D2 B8 " + absaddr + "ff d0 61 8b 4c 24 08 " + setJit
	ebcmd = "eb 0x%x %s" % (hook_address, xbytes)
	pykd.dbgCommand(ebcmd)
	
def writeHookNative(hook_address):
	"""Write the code for the setNative hook"""
	# 0:  60              pusha  					  # save registers
	# 1:  8B CE           mov  ecx,esi				  # esi = MethodInfo 
	# 3:  30 d2           xor  dl,dl
	# 5:  b8 XX XX XX XX  mov  eax,0xXXXXXXXX		  # load getMethodName 
	#												  # address
	# a:  ff d0           call eax				  	  # call getMethodName
	# c:  61              popa						  # restore registers
	# d:  8b 41 08	      mov eax,dword ptr [ecx+0x8] # first inst of setNative
	#
	absaddr = setNative = ""
	for b in struct.pack("<L",(func_addr['getMethodName'])):
		absaddr += hex(struct.unpack("B",b)[0]).split("0x")[1] + " "
	# plus 3 so we dont hit the BP again
	jmp = calcJmp(hook_address+0x10, func_addr['setNative']+0x3) 
	for b in jmp:
		setNative += hex(ord(b)).split("0x")[1] + " "
	xbytes = "60 8B CE 30 D2 B8 " + absaddr + "ff d0 61 8b 41 08 " + setNative
	ebcmd = "eb 0x%x %s" % (hook_address, xbytes)
	pykd.dbgCommand(ebcmd)

def writeHookInterp(hook_address):
	"""Write the code for the setNative hook"""
	# 0:  60              pusha  					  # save registers
	# 1:  89 D9           mov  ecx,ebx				  # ebx = MethodInfo
	# 1:  8b 4c 24 24	  mov  ecx,[esp+24]			  # poi(esp+24) = address of
	#												  # the func we want
	#												  # to name
	# 3:  30 d2           xor  dl,dl
	# 5:  b8 ff ff ff ff  mov  eax,0xffffffff		  # load getMethodName 
	#												  # address
	# a:  ff d0           call eax				  	  # call getMethodName
	# c:  61              popa						  # restore registers
	# d:  33 C0      	  xor eax, eax				  # first inst of setInterp
	#
	global NPS
	NPS["SetInterpRet"] = findAllocRets('setInterp', None, 
						 ["\xC2", "\x0C", "\x00"], True)[0]
	absaddr = setInterp = ""
	for b in struct.pack("<L",(func_addr['getMethodName'])):
		absaddr += hex(struct.unpack("B",b)[0]).split("0x")[1] + " "
	# plus 2 so we dont hit the BP again
	jmp = calcJmp(hook_address+0x11, func_addr['setInterp']+0x2) 
	for b in jmp:
		setInterp += hex(ord(b)).split("0x")[1] + " "
	xbytes = "60 8b 4c 24 24 30 D2 B8 " + absaddr + "ff d0 61 33 C0 " + setInterp
	ebcmd = "eb 0x%x %s" % (hook_address, xbytes)
	pykd.dbgCommand(ebcmd)

def hookHandlerInterpRet(methodName):
	"""..."""
	global GBP
	interpfunc = pykd.reg("eax") 
	if pykd.isValid(interpfunc):
		print "[#] INTERP STUB: at 0x%x \t offset: 0x%x \t\tName: %s" %\
			(interpfunc,0,methodName.decode("utf-8","replace"))
		if NPS["TraceInterp"] and methodName not in GBP['BP_FUNCS'] and\
				methodName not in GBP['BP_RFUNCS']:
			if NPS["Debug"]:
				print "[Debug] Setting bp for tracing on 0x%x" % interpfunc
			GBP[interpfunc] = pykd.setBp(interpfunc, lambda: functionHandler(methodName))
		func_breakpoints(methodName.decode("utf-8","replace"), interpfunc)		
	else:
		print "[!] No interp stub found. Something is likely wrong!!!"
	try:
		del GBP['INTERP_RET']
	except KeyError:
		pass
	return pykd.executionStatus.NoChange
	
def hookHandlerInterp():
	"""..."""
	global GBP
	# address of the func name as returned by getMethodName
	address = pykd.ptrPtr(pykd.reg("eax")+0x8) 
	if pykd.isValid(address):
		methodName = pykd.loadCStr(address)
		GBP['INTERP_RET'] = pykd.setBp((NPS["SetInterpRet"]-4), 
			lambda: hookHandlerInterpRet(methodName))
	return pykd.executionStatus.NoChange
				
def hookHandlerJit():
	"""Unlike setNative, setJit is a fairly simple in that the GprMethodProc
	parameted contains the resolved address of the jitted function.
	We simply need to read that register value."""
	global GBP
	# address of the func name as returned by getMethodName
	address = pykd.ptrPtr(pykd.reg("eax")+0x8) 
	# address of the jitted function
	jitfunc = pykd.ptrPtr(pykd.reg("esp")+0x28) 
	if pykd.isValid(address):
		methodName = pykd.loadCStr(address)
		if pykd.isValid(jitfunc):
			print "[&] JITTED METHOD: at 0x%x \t offset: 0x%x \t\tName: %s" %\
				(jitfunc,0,methodName.decode("utf-8","replace"))
			if NPS["TraceJit"] and methodName not in GBP['BP_FUNCS'] and\
					methodName not in GBP['BP_RFUNCS']:
				if NPS["Debug"]:
					print "[Debug] Setting bp for tracing on 0x%x" % jitfunc
				GBP[jitfunc] = pykd.setBp(jitfunc, lambda: functionHandler(methodName))
			func_breakpoints(methodName.decode("utf-8","replace"), jitfunc)		
		else:
			print "[!] No jitted function found. Something is likely wrong!!!"
	return pykd.executionStatus.NoChange

def hookHandlerNative():
	"""Address of the func name as returned by getMethodName is pointed by 
	EAX+0x08 However, unlike the published AVM source code claims, setNative 
	function in the NPSWF32 has an additional check before the correct function 
	address is assigned to the MethodInfo object. That logic is reimplemented 
	here."""
	global GBP
	address = pykd.ptrPtr(pykd.reg("eax")+0x8)
	comp_byte = pykd.ptrByte(pykd.ptrPtr(pykd.reg("esp")+0x18) + 0x38)  
	if comp_byte > 0:
		nativefunc = pykd.ptrPtr(pykd.reg("esi")+0x28)
	else:
		nativefunc = pykd.ptrPtr(pykd.reg("esi")+0x24)	
	if pykd.isValid(address):
		methodName = pykd.loadCStr(address)
		if pykd.isValid(nativefunc):
			print "[^] NATIVE METHOD: at 0x%x \t offset: 0x%x \tName: %s" % \
			(nativefunc,nativefunc-NPS['base_addr'], 
			 methodName.decode("utf-8","replace"))
			if NPS["TraceNative"] and methodName not in GBP['BP_FUNCS'] and\
					methodName not in GBP['BP_RFUNCS']:
				if NPS["Debug"]:
					print "[Debug] Setting bp for tracing on 0x%x" % nativefunc
				GBP[nativefunc] = pykd.setBp(nativefunc, lambda: functionHandler(methodName))
			func_breakpoints(methodName.decode("utf-8","replace"), nativefunc)			
		else:
			print "[!] No native function found. Something is likely wrong!!!"
	return pykd.executionStatus.NoChange	

def monitorHandler():
	"""Enable the global variable to log the monitored allocations"""
	global GBP
	GBP["START_ALLOC_MONITOR"] = True
	return pykd.executionStatus.NoChange
	
def functionHandler(methodName):
	"""Just log when a native/jitted function is executed if trace is enabled"""
	print "[*] Executing %s" % methodName
	return pykd.executionStatus.NoChange
	
def func_breakpoints(methodName, methodAddr):
	"""Set the appropriate breakpoints when instructed by the user through the 
	script options. Also set the appropriate breakpoints in the GC and 
	FixedMalloc allocator functions to monitor heap allocations when instructed 
	by the user through the script options."""
	global GBP
	# Normal breakpoints on complete function name 
	# like flash.display::LoaderInfo
	for func_name in GBP["BP_FUNCS"]:
		if func_name.lower() == methodName.lower():
				print "[*] Setting break point on %s at address: 0x%x" %\
					(methodName,methodAddr)
				#GBP[methodName] = pykd.setBp(methodAddr, 
				#							 lambda: functionHandler(methodName))
				pykd.dbgCommand("bp 0x%x" % methodAddr)
	# Breakpoints on any function matching a string like breakpoint on any 
	# function containing the string LoaderInfo
	for func_name in GBP["BP_RFUNCS"]:
		if (methodName.lower().find(func_name.lower()))!=-1:
				print "[*] Setting break point on %s at address: 0x%x" %\
					(methodName,methodAddr)
				#GBP[methodName] = pykd.setBp(methodAddr, 
				#							 lambda: functionHandler(methodName))
				pykd.dbgCommand("bp 0x%x" % methodAddr)
	# Heap monitor breakpoints
	if GBP["StartMonitorOnFunc"]:
		if (GBP["StartMonitorOnFunc"].lower().strip() ==\
				methodName.lower().strip()):
			if NPS['list_gcallocs']:
				monitorGCAlloc()
			if NPS['list_fmallocs']:
				monitorFixedMallocOutOfLineAlloc()
				monitorFixedMallocLargeAlloc()
				monitorFixedMalloc()
			if NPS['list_HeapAlloc']:
				monitorHeapAlloc()
			print "[+] Starting to monitoring allocations after method %s" %\
				methodName
			GBP["monitor_alloc_method"] = pykd.setBp(methodAddr, monitorHandler)

def bpHandlerInterp():
	"""..."""
	global NPS, GBP
	if not NPS['HOOK_INTERP']:
		# Allocate memory for our hook
		getMethodNameHook = int((pykd.dbgCommand(".dvalloc 1000").\
								split()[-1]),16)
		# Write the Interp hook
		print "[+] Interp Hook setup at address 0x%x" % getMethodNameHook
		writeHookInterp(getMethodNameHook)
		NPS['HOOK_INTERP'] = getMethodNameHook
		print "[+] Start hooking Interp Flash functions..."
	# Set the breakpoit right after getMethodName returns so that
	# we can read the resolved function name and address
	GBP['HOOK_INTERP'] = pykd.setBp(NPS['HOOK_INTERP']+0xe, hookHandlerInterp)
	# Redirect to our Interp hook
	pykd.dbgCommand("r eip=0x%x" % NPS['HOOK_INTERP'])
	return pykd.executionStatus.NoChange
	
def bpHandlerJit():
	"""Create and Install getMethodName hook
	void BaseExecMgr::setJit(MethodInfo* m, GprMethodProc p)
	Stringp MethodInfo::getMethodName(bool includeAllNamesplaces) const"""
	global NPS, GBP
	if not NPS['HOOK_JIT']:
		# Setting up alloc monitor if requested
		if NPS['list_gcallocs']:
			if not GBP["StartMonitorOnFunc"] :
				GBP["START_ALLOC_MONITOR"] = True
				monitorGCAlloc()
		if NPS['list_fmallocs']:
			if not GBP["StartMonitorOnFunc"] :
				GBP["START_ALLOC_MONITOR"] = True
				monitorFixedMallocOutOfLineAlloc()
				monitorFixedMallocLargeAlloc()
				monitorFixedMalloc()
		if NPS['list_HeapAlloc']:
			if not GBP["StartMonitorOnFunc"] :
				GBP["START_ALLOC_MONITOR"] = True
				monitorHeapAlloc()
		# Allocate memory for our hook
		getMethodNameHook = int((pykd.dbgCommand(".dvalloc 1000").\
								split()[-1]),16)
		print "[+] Jit Hook setup at address 0x%x" % getMethodNameHook
		# Write the Jit hook
		writeHookJit(getMethodNameHook)
		NPS['HOOK_JIT'] = getMethodNameHook
		print "[+] Start hooking Jitted Flash functions..."
	# Set the breakpoit right after getMethodName returns so that
	# we can read the resolved function name and address
	GBP['HOOK_JIT'] = pykd.setBp(NPS['HOOK_JIT']+0xc, hookHandlerJit)
	# Redirect to our Jit hook
	pykd.dbgCommand("r eip=0x%x" % NPS['HOOK_JIT'])
	return pykd.executionStatus.NoChange
	
def bpHandlerNative():
	"""Create and Install getMethodName hook
	void BaseExecMgr::setNative(MethodInfo* m, GprMethodProc p)
	Stringp MethodInfo::getMethodName(bool includeAllNamesplaces) const"""
	global NPS, GBP
	if not NPS['HOOK_NATIVE']:
		# Allocate memory for our hook
		getMethodNameHook = int((pykd.dbgCommand(".dvalloc 1000").\
								split()[-1]),16)
		# Write the Native hook
		print "[+] Native Hook setup at address 0x%x" % getMethodNameHook
		writeHookNative(getMethodNameHook)
		NPS['HOOK_NATIVE'] = getMethodNameHook
		print "[+] Start hooking Native Flash functions..."
	# Set the breakpoit right after getMethodName returns so that
	# we can read the resolved function name and address
	GBP['HOOK_NATIVE'] = pykd.setBp(NPS['HOOK_NATIVE']+0xc, hookHandlerNative)
	# Redirect to our Native hook
	pykd.dbgCommand("r eip=0x%x" % NPS['HOOK_NATIVE'])
	return pykd.executionStatus.NoChange

def allocHandlerFixedMalloc(ret_addr):
	"""Callback invoked when a FixedMalloc allcoation is requested.The function
	sets a breakpoint on the addresses within the function where the 
	allocation address is returned."""
	global GBP
	try:
		ret = ret_addr[pykd.reg("eip")]
		f_sig = pykd.dbgCommand("u 0x%x L1" % pykd.reg("eip"))
		# "0fdf1b82 81fef0070000    cmp     esi,7F0h"
		reg32 = f_sig.split()[-1].split(",")[0].strip()
		#print "[Debug] Signature: %s reg32: %s" % (signature, reg32)
		req_size = pykd.reg(reg32)
		GBP["FixedMallocBPs"][ret] = pykd.setBp(ret, 
							  lambda: allocServedFixedMalloc(ret, 
															 req_size))
		return pykd.executionStatus.NoChange
	except IndexError:
		print "[!] Could not extract the register for the follwing"\
"instruction: %s" % f_sig
		return pykd.executionStatus.Break		
		
def allocHandlerGCAlloc(rets):
	"""Callback invoked when a GC allocation is requested. The function
	sets a breakpoint on the addresses within the function where the 
	allocation address is returned."""
	global GBP
	req_size = pykd.ptrPtr(pykd.reg("esi")+0x20)
	GCAlloc = pykd.reg("ecx")
	#MMgc::GCAlloc::GCAlloc
	#mov     esi, ecx
	#...
	#mov     ecx, [esp+10h+SmallGCAllocHeapPartition]
	#mov     [esi+38h], edx
	#mov     [esi+3Ch], ecx  ; 0x3c is the partition index
	#mov     [esi+30h], eax
	if IsheapIsolVersion():
		Partition = pykd.ptrPtr(pykd.reg("esi")+0x3c)
	else:
		Partition = "NotImplemented"
	for ret in findAllocRets('GCAlloc::Alloc', func_sigs_ends['GCAllocEnd'], 
							 ["\xC2", "\x04", "\x00"]):
		GBP["GCAllocBPs"][ret] = pykd.setBp(ret, 
										lambda: allocServedGCAlloc(req_size, 
										ret, GCAlloc, Partition))
	return pykd.executionStatus.NoChange
	
def allocHandlerFixedMallocOutOfLineAlloc(rets):
	"""Callback invoked when a FixedMalloc OutOfLine allocation is requested. 
	The function sets a breakpoint on the addresses within the function where 
	the allocation address is returned. """
	global GBP
	req_size = pykd.reg("edx")
	for ret in rets:
		GBP[ret] = pykd.setBp(ret, 
					lambda: allocServedFixedMallocOutOfLineAlloc(req_size, ret))
	return pykd.executionStatus.NoChange

def allocHandlerFixedMallocLargeAlloc(rets):
	"""Callback invoked when a FixedMalloc Large allocation is requested. 
	The function sets a breakpoint on the addresses within the function where 
	the allocation address is returned."""
	global GBP
	req_size = pykd.reg("eax")
	FixedMalloc = pykd.reg("ecx")
	for ret in rets:
		GBP[ret] = pykd.setBp(ret, 
			lambda: allocServedFixedMallocLargeAlloc(req_size, ret, FixedMalloc))
	return pykd.executionStatus.NoChange

def allocServedGCAlloc(req_size, ret, GCAlloc, Partition):
	"""Callback invoked just before the GCAlloc function returns.
	EAX will store the allocation address"""
	global GBP
	allocaddress = pykd.reg("eax")
	GCAllocBase = pykd.ptrPtr((allocaddress & 0xfffff000)+0xC)
	returned_allocsize =  pykd.ptrPtr((allocaddress & 0xfffff000)+0x4)
	if GBP["START_ALLOC_MONITOR"]:
		if NPS['fgcsize']:
			if NPS['fgcsize'] == returned_allocsize:
				print "[GCAlloc::Alloc] Requested allocation 0x%x Returned \
allocation of size:0x%x at address: 0x%x: HeapPartition: %s" %\
				(req_size, returned_allocsize, allocaddress, Partition)
		else:
			print "[GCAlloc::Alloc] Requested allocation 0x%x Returned \
allocation of size:0x%x at address: 0x%x HeapPartition: %s" %\
			(req_size, returned_allocsize, allocaddress, Partition)
		GBP["AllocHistory"][allocaddress] = pykd.dbgCommand("kv") +\
		"\n\nRAW Stack data in case FPO is in place:\n\n" +\
		pykd.dbgCommand("dps esp L100")
	# Delete the breakpoints
	del GBP["GCAllocBPs"][ret]
	return pykd.executionStatus.NoChange
	
def allocServedFixedMallocOutOfLineAlloc(allocsize, ret):
	"""Callback invoked just before the FixedMalloc OutOfLine function returns.
	EAX will store the allocation address"""
	global GBP
	allocaddress = pykd.reg("eax")
	# If allocsize is greater than 0x7f0 the allocation will be served by 
	# FixedMalloc::LargeAlloc
	if allocsize <= 0x7f0:
		if GBP["START_ALLOC_MONITOR"]:
			returned_allocsize = pykd.ptrPtr((allocaddress & 0xfffff000)+0x12)
			# FixedAlloc allocator
			allocator = pykd.ptrPtr((allocaddress & 0xfffff000)+0x1C)
			# FixedAlloc.h#L120
			# GCHeap *m_heap;             //The heap from which we 
			#							  //obtain memory
			# int m_heapPartition;		  //The heap partition from which we
			#							  //obtain memory
			# uint32_t m_itemsPerBlock;   //Number of items that fit in a block
			# uint32_t m_itemSize;        //Size of each individual item
			# FixedBlock* m_firstBlock;   //First block on list of free blocks
			# FixedBlock* m_lastBlock;    //Last block on list of free blocks
			# FixedBlock* m_firstFree;    //The lowest priority block that has 
			#							  //free items
			# size_t    m_numBlocks;      //Number of blocks owned by this 
			#							  //allocator
			if IsheapIsolVersion():
				heapPartition =  pykd.ptrPtr(allocator+0x4)
			else:
				heapPartition = "NotImplemented"
			kSizeClass = kSizeClassIndex[((allocsize+7)>>3)]
			MMgc_FixedMalloc_obj =\
				allocator - kSizeClass*NPS["FixedAllocSafeSize"] -\
				NPS["m_allocs_offset"]
			if NPS['ffmsize']:
				if NPS['ffmsize'] == returned_allocsize:
					print "[FixedMalloc::OutOfLineAlloc] Requested Allocation \
of size:0x%x Returned allocation of size:0x%x at address:0x%x \
(MMgc::FixedMalloc Instance: 0x%x HeapPartition: %s)" % (allocsize, 
							returned_allocsize, allocaddress, 
							MMgc_FixedMalloc_obj, heapPartition)
			else:
				print "[FixedMalloc::OutOfLineAlloc] Requested Allocation of \
size:0x%x Returned allocation of size:0x%x at address:0x%x \
(MMgc::FixedMalloc Instance: 0x%x HeapPartition: %s)" % (allocsize, 
							returned_allocsize, allocaddress, 
							MMgc_FixedMalloc_obj, heapPartition)
			GBP["AllocHistory"][allocaddress] = pykd.dbgCommand("kv") +\
			"\n\n" +\
			"\n\nRAW Stack data in case FPO is in place:\n\n" +\
			pykd.dbgCommand("dps esp L100")
	# Delete the breakpoint
	del GBP[ret]
	return pykd.executionStatus.NoChange

def allocServedFixedMallocLargeAlloc(req_size, ret, FixedMalloc):
	"""Callback invoked just before the FixedMalloc Large function returns.
	EAX will store the allocation address"""
	global GBP
	# FixedMalloc::InitInstance
	# this->m_heap = MMgc::GCHeap;
	# this->m_largeAllocHeapPartition = fixedPartitionMap[partition];
	# m_largeAllocHeapPartition is at offset + 0x4
	if IsheapIsolVersion():
		Partition = pykd.ptrPtr((FixedMalloc+0x4))
	else:
		Partition = "NotImplemented"
	if GBP["START_ALLOC_MONITOR"]:
		returned_allocsize = ((req_size + 0xfff)>>0xC)*0x1000
		if NPS['ffmsize']:
			if NPS['ffmsize'] == returned_allocsize:
				print "[FixedMalloc::LargeAlloc] Requested Allocation of \
size:0x%x Returned allocation of size:0x%x at address:0x%x FixedMalloc:0x%x \
Partition: %s" %\
 (req_size, returned_allocsize, pykd.reg("eax"), FixedMalloc, Partition)
		else:
			print "[FixedMalloc::LargeAlloc] Requested Allocation of \
size:0x%x Returned allocation of size:0x%x at address:0x%x FixedMalloc:0x%x \
Partition: %s" %\
 (req_size, returned_allocsize, pykd.reg("eax"), FixedMalloc, Partition)
		GBP["AllocHistory"][pykd.reg("eax")] = pykd.dbgCommand("kv") +\
		"\n\nRAW Stack data in case FPO is in place:\n\n" +\
		pykd.dbgCommand("dps esp L100")
	return pykd.executionStatus.NoChange
	
def allocServedFixedMalloc(ret, req_size):
	"""Callback invoked just before the FixedMalloc function returns.
	poi(esi+4) will store the allocation address"""
	global GBP
	# Since we have different functions using the FixMalloc allocator 
	# we track the instruction pointer.
	eip = pykd.reg("eip") - NPS['base_addr']
	# 8B 5E 04          mov     ebx, [esi+4]
	# 8B 46 04          mov     eax, [esi+4]
	# 8B 6e 04          mov     ebp, [esi+4]
	allocaddress = pykd.ptrPtr(pykd.reg("esi")+0x4)
	# FixedMalloc pages store blocksize at +0x12 from the beginning of the page
	allocsize = pykd.ptrPtr((allocaddress & 0xfffff000)+0x12)
	# A pointer to the FixedAlloc array entry is stored at +0x1C from the 
	# beginning of the memory page
	allocator = pykd.ptrPtr((allocaddress & 0xfffff000)+0x1C)
	kSizeClass = kSizeClassIndex[((allocsize+7)>>3)]
	# From the FixedAlloc entry we calculate the offset to go back to the 
	# FixedMalloc object instance pointer. This can be used to see if a specific
	# allocation belongs to a particular heap and is isolated from other 
	# allocations
	#MMgc_FixedMalloc_obj = allocator - kSizeClass*0x28 - 8
	MMgc_FixedMalloc_obj =\
		allocator - kSizeClass*NPS["FixedAllocSafeSize"] -\
		NPS["m_allocs_offset"]
	# FixedAlloc.h#L120
	# GCHeap *m_heap;             //The heap from which we 
	#							  //obtain memory
	# int m_heapPartition;		  //The heap partition from which we
	#							  //obtain memory
	# uint32_t m_itemsPerBlock;   //Number of items that fit in a block
	# uint32_t m_itemSize;        //Size of each individual item
	# FixedBlock* m_firstBlock;   //First block on list of free blocks
	# FixedBlock* m_lastBlock;    //Last block on list of free blocks
	# FixedBlock* m_firstFree;    //The lowest priority block that has 
	#							  //free items
	# size_t    m_numBlocks;      //Number of blocks owned by this 
	#							  //allocator
	if IsheapIsolVersion():
		heapPartition = pykd.ptrPtr(allocator+0x4)
	else:
		heapPartition = "NotImplemented"
	if req_size <= 0x7f0: 
		if GBP["START_ALLOC_MONITOR"]:
			if NPS['ffmsize']:
				if NPS['ffmsize'] == allocsize:
					print "[FixedMalloc::Alloc] Requested Allocation of \
size:0x%x Returned allocation of size:0x%x at address:0x%x \
(MMgc::FixedMalloc Instance:0x%x, HeapPartition: %s) NPSWF32 OFFSET=0x%x" %\
 (req_size, allocsize, allocaddress, MMgc_FixedMalloc_obj, eip, heapPartition)
			else:
				print "[FixedMalloc::Alloc] Requested Allocation of \
size:0x%x Returned allocation of size:0x%x at address:0x%x \
(MMgc::FixedMalloc Instance:0x%x) NPSWF32 OFFSET=0x%x HeapPartition: %s" %\
 (req_size, allocsize, allocaddress, MMgc_FixedMalloc_obj, eip, heapPartition)
			GBP["AllocHistory"][allocaddress] = pykd.dbgCommand("kv") +\
			"\n\nRAW Stack data in case FPO is in place:\n\n" +\
			pykd.dbgCommand("dps esp L100")
	# Delete breakpoint 
	del GBP["FixedMallocBPs"][ret]
	return pykd.executionStatus.NoChange	
	
def allocServedHeapAllocSystemRet(size, heap, tid):
	"""Callback invoked before HeapAlloc returns to intercept the 
	allocation address"""
	global GBP
	print "[HeapAlloc] Requested Allocation of size 0x%x \
on Heap 0x%x address 0x%x Thread: 0x%x" %\
		(size, heap, pykd.reg("eax"), tid)
	GBP["AllocHistory"][pykd.reg("eax")] = pykd.dbgCommand("kv") +\
	"\n\nRAW Stack data in case FPO is in place:\n\n" +\
	pykd.dbgCommand("dps esp L100")
	del GBP["HeapAllocRet"]
			
def allocServedHeapAllocSystem():
	"""Callback invoked when HeapAlloc is called."""
	global GBP
	if GBP["START_ALLOC_MONITOR"]:
		# LPVOID WINAPI HeapAlloc(
		  # _In_ HANDLE hHeap,
		  # _In_ DWORD  dwFlags,
		  # _In_ SIZE_T dwBytes
		# );
		size = pykd.ptrPtr(pykd.reg("esp")+0xC)
		heap = pykd.ptrPtr(pykd.reg("esp")+0x4)
		tid  = pykd.getCurrentThreadId() 
		if NPS['ihsize']:
			if NPS['ihsize'] == size:
				# Setup a breakpoint on the return address
				GBP["HeapAllocRet"] = pykd.setBp(pykd.ptrPtr(pykd.reg("esp")), 
					lambda: allocServedHeapAllocSystemRet(size, heap, tid))
		else:
			# Setup a breakpoint on the return address
			GBP["HeapAllocRet"] = pykd.setBp(pykd.ptrPtr(pykd.reg("esp")), 
				lambda: allocServedHeapAllocSystemRet(size, heap, tid))
	return pykd.executionStatus.NoChange
			
def getModuleSize(module):
	"""Getting the size of the module to perform memory searches"""
	global NPS
	print "[+] Getting module size..."
	if module == 'NPS':
		mod = pykd.module(NPS['base_addr'])
		NPS['size'] = mod.size()
		NPS['end_addr'] = NPS['base_addr'] + NPS['size']
		print "[+] NPSBASE FOUND 0x%x, NPS_SIZE 0x%x, NPS_END 0x%x" %\
			(NPS['base_addr'], NPS['size'], NPS['end_addr'])

def findFuncs(module):
	"""Wrapper for the function finding routine"""
	if module == 'NPS':
		for k in func_sigs:
			findFunc(k, 'func_sigs')
		for k in fixedmalloc_funcs_sigs:
			findFunc(k, 'fixedmalloc_funcs_sigs')
			
def findFunc(sig, type):
	"""This routine will scan the memory to find the functions needed to set 
	breakpoints on jitted and native functions as well as monitoring 
	allocations."""
	global NPS
	#create a hex tag from the sig
	if type == 'func_sigs':
		tag = func_sigs[sig].split()
	elif type == 'fixedmalloc_funcs_sigs':
		tag = fixedmalloc_funcs_sigs[sig].split()
	else:
		print "[!] Bad signature dictionary type passed"
		return
	tag = [struct.pack("B",int(item,16)) for item in tag]
	results = []
	base = int(NPS['base_addr'])
	size = int(NPS['size'])
	end  = base + size
	res_addr = pykd.searchMemory(base, size, tag)
	while res_addr:
		if res_addr:
			results.append(res_addr)
		base = res_addr + len(tag)
		size = end - base
		res_addr = pykd.searchMemory(base, size, tag)
	
	if len(results):
		[long(item) for item in results]
		# MORE THAN ONE FUNCTION HAS THE SPECIFIC SIGNATURE
		if len(results)>1:
			# DEBUG
			# We should have only one signature with cmp edx,7F0h
			# and that is FixedMalloc::OutOfLineAlloc
			if sig == "cmp edx,7F0h":
				if NPS["Debug"]:
					print "[Debug] Warning! Found more than one signature with\
 cmp edx, 0x7F0. Usually only OutOfLineAlloc has this signature!"
				# we don't want to end up with the same function twice
				del results[
					results.index(func_addr['FixedMalloc::OutOfLineAlloc'])]
			func_addr[sig] = results
			for sig_address in results:
				if NPS["Debug"]:
					print "[Debug] 0x%x contains %s signature." %\
					((sig_address-NPS['base_addr']), sig)
		# ONLY ONE FUNC WITH THE SPECIFIC SIGNATURE
		else:
			# DEBUG: We keep this signature only for the OutOfLineAlloc
			# Otherwise we end up with the same function twice
			if sig != "cmp edx,7F0h":
				func_addr[sig] = results[0]
				if NPS["Debug"]:
					print "[Debug] 0x%x contains %s function." %\
					((func_addr[sig]-NPS['base_addr']), sig)
			else:
				if NPS["Debug"]:
					print "[Debug] Discarding 0x%x as it's OutOfLineAlloc" %\
					(results[0]-NPS['base_addr'])
	else:
		if NPS["Debug"]:
			print "[Debug] %s NOT found" % sig

def findAllocRets(Allocator, AllocEnd, RetIns, OneRet=None, 
				  Name=None, OptRetIns=None):
	"""Starting from the beginning of the allocator find all the return
	instructions in order to put breakpoints and intercept the returned 
	allocation address. We either search for all ret instructions specified by 
	"RetIns" until we find the AllocEnd instruction, or search for the only ret 
	instruction if OneRet=True. If RetIns is not found and OptRetIns is 
	specified a further search is performed.
	"""
	rets = []
	if isinstance(Allocator, (long,)):
		start = Allocator
	else:
		start = func_addr[Allocator]
	if OneRet:
		tmp = start
		res2 = None
		while not res2:
			res2 = pykd.searchMemory(start, len(RetIns), RetIns)
			if not res2 and OptRetIns:
				for ori in OptRetIns:
					res2 = pykd.searchMemory(start, len(ori), ori)
					if res2:
						break
			if res2:
				rets.append(res2)
				return rets
			else:
				start += 1
		if not rets:
			print "[-] Could not find the return instruction for %s" % Allocator
			return rets
	tag = AllocEnd.split()
	tag = [struct.pack("B",int(item,16)) for item in tag]
	
	res1 = pykd.searchMemory(start, len(tag), tag)
	res2 = pykd.searchMemory(start, len(RetIns), RetIns)

	while not res1:
		if res2 and res2 not in rets:
			rets.append(res2)
		start += 1
		res1 = pykd.searchMemory(start, len(tag), tag)
		res2 = pykd.searchMemory(start, len(RetIns), RetIns)
	if not rets:
		print "[-] Could not find the return instruction for %s" % Allocator
	return rets

def BPsSet():
	"""List breakpoint sets through setBp API."""
	BPs = []
	for i in xrange(0, pykd.getNumberBreakpoints()):
		BPs.append(pykd.getBp(i).getOffset())
	return BPs
	
def monitorGCAlloc():
	"""Start monitoring allocations MMgc::GCAlloc::Alloc"""
	global GBP
	rets = findAllocRets('GCAlloc::Alloc', 
							func_sigs_ends['GCAllocEnd'], 
							 ["\xC2", "\x04", "\x00"])
	GBP["GCAllocSize"] = pykd.setBp(func_addr["GCAlloc::Alloc"], 
		lambda: allocHandlerGCAlloc(rets))
					
def monitorFixedMalloc():
	"""General monitor for FixedMalloc allocations"""
	global GBP
	start = time.time()
	ret_addr = {}
	for f_sig in fixedmalloc_funcs_sigs.keys():
		try:
			f_start = func_addr[f_sig]
		except:
			continue
		# the function start (f_start) identified by the signature can either
		# be an address or a list of addresses in case findFunc found more
		# entries with that specific signature.
		if isinstance(f_start, (long,)):
			f_start = [f_start,]
		
		# For each f_start we try to find the place in the function where the 
		# allocation is pulled from the free allocations linked list for
		# a specific memory page at page_start+4. According to our tests,
		# we can have 3 specific cases/signatures in which the pointer to the 
		# head of the free list at poi(page_start+4) is copied to either ebx, 
		# ebp or eax.
		# RetIns (Return Instruction)
		# 8B 5E 04          mov     ebx, [esi+4]
		# OptRetIns (Optional Return Instructions):
		# 8B 6E 04          mov     ebp, [esi+4]
		# 8B 46 04          mov     eax, [esi+4]
		for i in f_start:
			rets = findAllocRets(i, None,  ["\x8B", "\x5E", "\x04"], 
								  True, "FixedMalloc", 
								  (["\x8B", "\x6E", "\x04"], 
								   ["\x8B", "\x46", "\x04"]))
			if len(rets) > 1:
				if NPS["Debug"]:
					print "[Debug] More than one mov reg32, [esi+4] found!"
			ret_addr[i] = rets[0]
			GBP[i] = pykd.setBp(i, lambda: allocHandlerFixedMalloc(ret_addr))
	if NPS["Debug"]:
		print "[*] %d seconds to complete the search and bps" %\
			(time.time()-start)
		
def monitorFixedMallocOutOfLineAlloc():
	"""Start monitoring allocations MMgc::FixedMalloc::OutOfLineAlloc"""
	global GBP
	rets = findAllocRets('FixedMalloc::OutOfLineAlloc', 
						 func_sigs_ends['FixedMallocEnd'], 
						["\xC2", "\x04", "\x00"])
	GBP["FixedMallocSize"] =\
		pykd.setBp(func_addr["FixedMalloc::OutOfLineAlloc"], 
				   lambda: allocHandlerFixedMallocOutOfLineAlloc(rets))
		
def monitorFixedMallocLargeAlloc():
	"""Start monitoring allocations MMgc::FixedMalloc::LargeAlloc"""
	global GBP
	rets = findAllocRets('FixedMalloc::LargeAlloc', None, 
						 ["\xC2", "\x08", "\x00"], True)
	GBP["FixedMallocLargeSize"] =\
		pykd.setBp(func_addr["FixedMalloc::LargeAlloc"], 
				   lambda: allocHandlerFixedMallocLargeAlloc(rets))
		
def monitorHeapAlloc():
	"""Start monitoring allocations for the HeapAlloc"""
	global GBP
	ntdll = pykd.module( "ntdll" )
	HeapAllocAddress = ntdll.offset("RtlAllocateHeap")
	GBP[HeapAllocAddress] = pykd.setBp(HeapAllocAddress, 
									   allocServedHeapAllocSystem)

def findAddress(address):
	"""Find an allocation in the alloc history dictionary and 
	   print the relative call stack"""
	try:
		address = int(address, 16)
	except Exception, e:
		print "[-] Exception: " + str(e)
		return
	temp = tempfile.gettempdir()
	fname = os.path.join(temp, "fldbgtmp.bin")
	try:
		fp = open(fname, "rb")
		alloc_history = pickle.load(fp)
		fp.close()
		if address in alloc_history.keys():
			print "[+] Alloction Call Stack for 0x%x:" % address
			print alloc_history[address]
		else:
			print "[!] The specified address is not in allocation history file"
			for k in alloc_history.keys():
				print hex(k)
	except Exception, e:
		print "[!] " + str(e)
									   
def parse_options():
	global NPS, GBP
	parser = OptionParser(usage='usage: %prog [options]')
	parser.add_option('-f', '--bp-on-func', action='store', 
						type='string', dest='funcs', default="", 
						help='functions on which we want to set a BP;\
comma delimited')
	parser.add_option('-r', '--bp-on-rfunc', action='store', type='string', 
						dest='rfuncs', default="", 
						help='functions on which we want to set a BP;\
comma delimited wildcard functions name')
	parser.add_option('-o', '--bp-on-offset', action='store', type='string', 
						dest='offsets', 
						help='offsets on which we want to set a BP;\
comma delimited')			  
	parser.add_option('-j', '--list-jit', action='store_true', dest='jit', 
						default=False,
	                    help='by default we don\'t list jitted functions')
	parser.add_option('-n', '--list-native', action='store_true', dest='native', 
						default=False,
	                    help='by default we don\'t list native functions')
# Partially working atm..	                    
#	parser.add_option('-z', '--list-interp', action='store_true', dest='interp', 
#					    default=False,
#                        help='by default we don\'t list interp functions')
	parser.add_option('-l', '--list-fixedmalloc', action='store_true', 
						dest='fixedmalloc', default=False,
	                    help='by default we don\'t monitor FixedMalloc \
allocations')	
	parser.add_option('-g', '--list-gcalloc', action='store_true', 
						dest='gcalloc', default=False,
	                    help='by default we don\'t monitor GC allocations')
	parser.add_option('-i', '--list-HeapAlloc', action='store_true', 
						dest='HeapAlloc', default=False,
	                    help='by default we don\'t monitor HeapAlloc \
allocations')	
	parser.add_option('-F', '--list-allocs-on-func', action='store', 
						type='string', dest='alloc_func', default="", 
						help='Jiited/Native function from which we want to \
start monitor allocations')
	parser.add_option('-S', '--filter-gc-by-size', action='store', type='int',
						dest='fgcsize', default=None, 
						help='filter monitored allocation by size')	
	parser.add_option('-s', '--filter-fixedmalloc-by-size', action='store', 
						type='int', dest='ffmsize', default=None, 
						help='filter monitored allocation by size')
	parser.add_option('-I', '--filter-HeapAlloc-by-size', action='store', 
						type='int', dest='ihsize', default=None, 
						help='filter monitored allocation by size')
	parser.add_option('-J', '--trace-jit', action='store_true', 
						dest='tracejit', default=False,
	                    help='by default we don\'t trace jitted functions')
	parser.add_option('-N', '--trace-native', action='store_true', 
						dest='tracenative', default=False,
	                    help='by default we don\'t trace native functions')		
#	parser.add_option('-Z', '--trace-interp', action='store_true', 
#					    dest='traceinterp', default=False,
#                       help='by default we don\'t trace interp functions')
	parser.add_option('-k', '--call-stack-alloc', action='store', type='string', 
						dest='callstack', default="", 
						help='find callstack for a specific allocation')
	parser.add_option('-d', '--debug', action='store_true', dest='debug', 
						default=False, help='Print debug info')						

	options, args = parser.parse_args()
	if options.callstack:
		address_to_find = options.callstack
		findAddress(address_to_find)
		return False
	
	GBP['BP_OFFSETS'] = GBP['BP_FUNCS'] = GBP['BP_RFUNCS'] = [] 
	if options.offsets:
		temp = options.offsets.split(",")
		for i in temp:
			try:
				k = int(i,16)
				GBP['BP_OFFSETS'].append(k)
			except:
				parser.error("Invalid offset entered")
					
	NPS['list_jit'] = options.jit
	NPS['list_native'] = options.native
	#NPS['list_interp'] = options.interp
	NPS['list_interp'] = None
	NPS['list_fmallocs'] = options.fixedmalloc
	NPS['list_HeapAlloc'] = options.HeapAlloc
	NPS['list_gcallocs'] = options.gcalloc
	NPS['ffmsize'] = options.ffmsize
	NPS['fgcsize'] = options.fgcsize
	NPS['ihsize'] = options.ihsize
	NPS["TraceNative"] = options.tracenative
	#NPS["TraceInterp"] = options.traceinterp
	NPS["TraceInterp"] = None
	NPS["TraceJit"] = options.tracejit
	NPS["Debug"] = options.debug
	if NPS['fgcsize']:
		print "[$] Filtering GC allocations of size 0x%x" % NPS['fgcsize'] 
	if NPS['ffmsize']:
		print "[$] Filtering FixedMalloc allocations of size 0x%x" %\
				NPS['ffmsize']
	if NPS['ihsize']:
		print "[$] Filtering HeapAlloc allocations of size 0x%x" % NPS['ihsize'] 			
	# if we want to set bp on functions, enable listing of jit/native functions
	if options.funcs:
		GBP['BP_FUNCS'] = options.funcs.split(",")
		#NPS['list_jit'] = NPS['list_native'] = NPS['list_interp'] = True
		NPS['list_jit'] = NPS['list_native'] = True
	else:
		GBP['BP_FUNCS'] = []
	if options.rfuncs:
		GBP['BP_RFUNCS'] = options.rfuncs.split(",")
		#NPS['list_jit'] = NPS['list_native'] = NPS['list_interp'] = True
		NPS['list_jit'] = NPS['list_native'] = True
	else:
		GBP['BP_RFUNCS'] = []
	if options.alloc_func:
		NPS['list_jit'] = NPS['list_native'] = True
		GBP["StartMonitorOnFunc"] = options.alloc_func
	else:
		GBP["StartMonitorOnFunc"] = None
		
	if NPS['list_gcallocs'] or NPS['list_fmallocs'] or NPS['list_HeapAlloc']:
		#NPS['list_jit'] = NPS['list_native'] = NPS['list_interp'] = True
		NPS['list_jit'] = NPS['list_native'] = True
	return True
	
# Debug browser child processes...
pykd.dbgCommand(".childdbg 1")
# Avoid Windbg to attempt downloading NPSWF32 symbols, set to random path... 
pykd.dbgCommand(".sympath SRV*c:\\d41d8cd98f00b204e9800998ecf8427e*")


if parse_options():
	while True:	
		# # We need to wait for the second instance of the target DLL
		if NPS['count'] == 2:			
			# A custom exception handler can be handy to automate the analysis
			# at the moment we don't need it though.
			# pykd.dbgCommand("sxd av")
			# exc = ExceptionHandler()	
			
			# Calculate module bounds that we will use for function searches
			getModuleSize('NPS')
			# Find the addresses of our functions
			findFuncs('NPS')
			# check for any options		
			#parse_options()
			if NPS['list_jit'] or NPS["TraceJit"]:
				# Start resolving Jitted functions
				GBP["bpHandlerJit"] = pykd.setBp(func_addr["setJit"], bpHandlerJit)
			if NPS['list_native'] or NPS["TraceNative"]:
				# Start resolving Native functions
				GBP["bpHandlerNative"] = pykd.setBp(func_addr["setNative"], 
													bpHandlerNative) 
			if NPS['list_interp'] or NPS["TraceInterp"]:
				# Start resolving Interp functions
				GBP["bpHandlerInterp"] = pykd.setBp(func_addr["setInterp"], 
													bpHandlerInterp)
			for offset in GBP['BP_OFFSETS']:
				print "[*] Setting break point at address: 0x%x" %\
					(NPS['base_addr']+offset)
				#GBP[offset] = pykd.setBp(NPS['base_addr']+offset, None)	
				cmd = "bp 0x%x" % (NPS['base_addr']+offset)
				pykd.dbgCommand(cmd)			
			break		
		#set up our module load handler
		modLoadHandler = ModuleLoadHandler(NPS['filename'])
		pykd.go()
		del modLoadHandler

	#start the party
	pykd.go()
	#save alloc history if there's any
	try:
		if GBP["AllocHistory"]:
			temp = tempfile.gettempdir()
			if NPS["Debug"]:
				print "[Debug] TemfileDir: %s" % temp
			fname = os.path.join(temp, "fldbgtmp.bin")
			if NPS["Debug"]:
				print "[Debug] TempFile: %s" % fname
			fp = open(fname, "wb")
			pickle.dump(GBP["AllocHistory"], fp)
			fp.close()
		else:
			print "[*] No Allocation history found"
	except Exception, e:
		print "[-] Exception " + str(e)
pykd.dbgCommand(".sympath cache*;SRV*https://msdl.microsoft.com/download/symbols")
pykd.dbgCommand(".reload")