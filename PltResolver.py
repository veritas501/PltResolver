#coding=utf8
#author: veritas501
import idc
import idaapi
import idautils

def SetFuncFlags(ea):
	func_flags=idc.GetFunctionFlags(ea)
	func_flags|=0x84 # FUNC_THUNK|FUNC_LIB
	idc.SetFunctionFlags(ea,func_flags)

def PltResolver64():
	def GetDyn():
		phoff = idc.Qword(idc.MinEA()+0x20)+idc.MinEA()
		phnum = idc.Word(idc.MinEA()+0x38)
		phentsize = idc.Word(idc.MinEA()+0x36)
		for i in range(phnum):
			p_type = idc.Dword(phoff+phentsize*i)
			if p_type == 2: # PY_DYNAMIC
				dyn_addr = idc.Qword(phoff+phentsize*i+0x10)
				return dyn_addr

	def ParseDyn(dyn,tag):
		idx=0
		while True:
			v1,v2 = idc.Qword(dyn+idx*0x10),idc.Qword(dyn+idx*0x10+8)
			if v1 == 0 and v2 == 0:
				return
			if v1 == tag:
				return v2
			idx+=1
	
	def __PltResolver(jmprel,strtab,symtab):
		idx=0
		while True:
			r_off = idc.Qword(jmprel+0x18*idx)
			r_info1 = idc.Dword(jmprel+0x18*idx+0x8)
			r_info2 = idc.Dword(jmprel+0x18*idx+0xc)
			r_addend = idc.Qword(jmprel+0x18*idx+0x10)
			if r_off > 0x7fffffff:
				return
			if r_info1 == 7:
				st_name = idc.Dword(symtab+r_info2*0x18)
				name = idc.GetString(strtab+st_name)
				# rename got
				idc.set_name(r_off,name+'_ptr')
				plt_func = idc.Qword(r_off)
				# rename plt
				idc.set_name(plt_func,'j_'+name)
				SetFuncFlags(plt_func)
				# rename plt.sec
				for addr in idautils.DataRefsTo(r_off):
					plt_sec_func = idaapi.get_func(addr)
					if plt_sec_func:
						plt_sec_func_addr = plt_sec_func.startEA
						idc.set_name(plt_sec_func_addr,'_'+name)
						SetFuncFlags(plt_sec_func_addr)
					else:
						print "[!] idaapi.get_func({}) failed".format(hex(addr))
			idx+=1

	dyn = GetDyn()
	if not dyn:
		print "[-] can't find symbol '_DYNAMIC'"
		return
	jmprel = ParseDyn(dyn,0x17)
	strtab = ParseDyn(dyn,0x5)
	symtab = ParseDyn(dyn,0x6)
	if not jmprel:
		print "[-] can't find 'DT_JMPREL' in '_DYNAMIC'"
		return
	if not strtab:
		print "[-] can't find 'DT_STRTAB' in '_DYNAMIC'"
		return
	if not symtab:
		print "[-] can't find 'DT_SYMTAB' in '_DYNAMIC'"
		return
	__PltResolver(jmprel,strtab,symtab)

def PltResolver32():
	def GetDyn():
		phoff = idc.Dword(idc.MinEA()+0x1c)+idc.MinEA()
		phnum = idc.Word(idc.MinEA()+0x2c)
		phentsize = idc.Word(idc.MinEA()+0x2a)
		for i in range(phnum):
			p_type = idc.Dword(phoff+phentsize*i)
			if p_type == 2: # PY_DYNAMIC
				dyn_addr = idc.Dword(phoff+phentsize*i+8)
				return dyn_addr

	def ParseDyn(dyn,tag):
		idx=0
		while True:
			v1,v2 = idc.Dword(dyn+idx*0x8),idc.Dword(dyn+idx*0x8+4)
			if v1 == 0 and v2 == 0:
				return
			if v1 == tag:
				return v2
			idx+=1

	def __PltResolver(jmprel,strtab,symtab,pltgot):
		seg_sec = idc.SegByName('.plt.sec')
		sec_start = idc.SegByBase(seg_sec)
		sec_end = idc.SegEnd(sec_start)
		if sec_start == idaapi.BADADDR:
			print "[-] can't find .plt.sec segment"
			return
		idx=0
		while True:
			r_off = idc.Dword(jmprel+0x8*idx)
			r_info1 = idc.Byte(jmprel+0x8*idx+0x4)
			r_info2 = idc.Byte(jmprel+0x8*idx+0x5)
			if r_off > 0x7fffffff:
				return
			if r_info1 == 7:
				st_name = idc.Dword(symtab+r_info2*0x10)
				name = idc.GetString(strtab+st_name)
				# rename got
				idc.set_name(r_off,name+'_ptr')
				plt_func = idc.Dword(r_off)
				# rename plt
				idc.set_name(plt_func,'j_'+name)
				SetFuncFlags(plt_func)
				# rename plt.sec
				for addr in idautils.DataRefsTo(r_off):
					plt_sec_func = idaapi.get_func(addr)
					if plt_sec_func:
						plt_sec_func_addr = plt_sec_func.startEA
						idc.set_name(plt_sec_func_addr,'_'+name)
						SetFuncFlags(plt_sec_func_addr)
					else:
						print "[!] idaapi.get_func({}) failed".format(hex(addr))
				got_off = r_off-pltgot
				target = '+{}h'.format(hex(got_off).lower().replace('0x','').replace('l','').rjust(2,'0'))
				for func_ea in idautils.Functions(sec_start,sec_end):
					func = idaapi.get_func(func_ea)
					cur = func.startEA
					end = func.endEA
					find=False
					while cur <= end:
						code = idc.GetDisasm(cur).lower().replace(' ','')
						if target in code:
							find=True
							break
						cur = idc.NextHead(cur, end)
					if find:
						idc.set_name(func_ea,'_'+name)
						SetFuncFlags(func_ea)
			idx+=1

	dyn = GetDyn()
	if not dyn:
		print "[-] can't find symbol '_DYNAMIC'"
		return
	jmprel = ParseDyn(dyn,0x17)
	strtab = ParseDyn(dyn,0x5)
	symtab = ParseDyn(dyn,0x6)
	pltgot = ParseDyn(dyn,0x3)
	if not jmprel:
		print "[-] can't find 'DT_JMPREL' in '_DYNAMIC'"
		return
	if not strtab:
		print "[-] can't find 'DT_STRTAB' in '_DYNAMIC'"
		return
	if not symtab:
		print "[-] can't find 'DT_SYMTAB' in '_DYNAMIC'"
		return
	if not pltgot:
		print "[-] can't find 'DT_PLTGOT' in '_DYNAMIC'"
		return
	__PltResolver(jmprel,strtab,symtab,pltgot)

class PltResolver_handler(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)

	def activate(self, ctx):
		arch = idc.Word(idc.MinEA()+0x12)
		if arch == 0x3E: # EM_X86_64
			PltResolver64()
		elif arch == 0x3: # EM_386
			PltResolver32()
		else:
			print '[-] Only support EM_X86_64 and EM_386'
		return 1

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

class PltResolver(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE
	comment = 'pltResolver'
	help = ''
	wanted_name = 'pltResolver'
	wanted_hotkey = ''

	def init(self):
		idaapi.msg('===================================================\n')
		idaapi.msg('pltResolver plugin has been loaded.\n')
		idaapi.msg('Press Ctrl+Shift+J to resolve .plt.sec symbols.\n')
		idaapi.msg('===================================================\n')

		idaapi.register_action(idaapi.action_desc_t('pltResolver:pltResolver', 'Parse .plt.sec symbols', PltResolver_handler(), 'Ctrl+Shift+J', None, 25))#注册action
		idaapi.attach_action_to_menu('Edit/pltResolver', 'pltResolver:pltResolver', idaapi.SETMENU_APP)#将action添加到menu

		return idaapi.PLUGIN_KEEP

	def term(self):#析构
		idaapi.unregister_action('pltResolver:pltResolver')

	def run(self,arg):
		pass


def PLUGIN_ENTRY():
	return PltResolver()
