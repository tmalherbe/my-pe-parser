#!/usr/bin/python3

import os
import sys

global verbose

machine_type_dict = {0x0: "The content of this field is assumed to be applicable to any machine type", 0x184 : "Alpha AXP, 32-bit address space", 0x284 : "Alpha 64, 64-bit address space", 0x1d3: "Matsushita AM33", 0x8664: "x64", 0x1c0: "ARM little endian", 0xaa64: "ARM64 little endian", 0x1c4: "ARM Thumb-2 little endian", 0x284: "AXP 64 (Same as Alpha 64)", 0xebc: "EFI byte code", 0x14c: "Intel 386 or later processors and compatible processors", 0x200: "Intel Itanium processor family", 0x6232: "LoongArch 32-bit processor family", 0x6264: "LoongArch 64-bit processor family", 0x9041: "Mitsubishi M32R little endian", 0x266: "MIPS16", 0x366: "MIPS with FPU", 0x466: "MIPS16 with FPU", 0x1f0: "Power PC little endian", 0x1f1: "Power PC with floating point support", 0x166: "MIPS little endian", 0x5032: "RISC-V 32-bit address space", 0x5064: "RISC-V 64-bit address space", 0x5128: "RISC-V 128-bit address space", 0x1a2: "Hitachi SH3", 0x1a3: "Hitachi SH3 DSP", 0x1a6: "Hitachi SH4", 0x1a8: "Hitachi SH5", 0x1c2: "Thumb", 0x169: "MIPS little-endian WCE v2"}

magic_dict = {0x10b: "32-bits executable", 0x20b: "64-bits executable", 0x107: "ROM image"}

subsystem_dict = {0x00: "Unknown subsystem", 0x01: "No subsystem required", 0x02: "Windows GUI subsystem", 0x03: "Windows character-mode subsystem", 0x05: "OS/2 CUI subsystem", 0x07: "POSIX CUI subsystem", 0x09: "Windows CE system", 0x0a: "EFI application", 0x0b: "EFI driver with boot services", 0x0c: "EFI driver with run-time services", 0x0d: "EFI ROM image", 0x0e: "Xbox system", 0x10: "Boot application"}

def hexdump(array, offset, size):

   for i in range (size // 32):
      buff = array[offset + i * 32 : offset + i * 32 + 32]
      print(f"\t\t{buff}") 	

   if size % 32 != 0:
   	print(f"\t\t{array[offset + (size//32) * 32 : size]}")

def get_dict_entry(dictionnary, key, category):
   try:
      return dictionnary[key]
   except KeyError:
      return f"unknown {category}"

def e_get_machine(elf_machine):
   return get_dict_entry(machine_type_dict, elf_machine, "machine type")

def e_get_optional_magic(magic):
   return get_dict_entry(magic_dict, magic, "optional header magic")

def e_get_sybsystem(subsystem):
  return get_dict_entry(subsystem_dict, subsystem, "subsystem")

def parse_Characteristics(Characteristics):
   char_meaning = list()

   if Characteristics & 0x01:
      char_meaning.append("IMAGE_FILE_RELOCS_STRIPPED")
   if Characteristics & 0x02:
      char_meaning.append("IMAGE_FILE_EXECUTABLE_IMAGE")
   if Characteristics & 0x04:
      char_meaning.append("IMAGE_FILE_LINE_NUMS_STRIPPED")
   if Characteristics & 0x08:
      char_meaning.append("IMAGE_FILE_LOCAL_SYMS_STRIPPED")
   if Characteristics & 0x10:
      char_meaning.append("IMAGE_FILE_AGGRESSIVE_WS_TRIM")
   if Characteristics & 0x20:
      char_meaning.append("IMAGE_FILE_LARGE_ADDRESS_ AWARE")
   if Characteristics & 0x40:
      char_meaning.append("RFU")
   if Characteristics & 0x80:
      char_meaning.append("IMAGE_FILE_BYTES_REVERSED_LO")
   if Characteristics & 0x100:
      char_meaning.append("IMAGE_FILE_32BIT_MACHINE")
   if Characteristics & 0x200:
      char_meaning.append("IMAGE_FILE_DEBUG_STRIPPED")
   if Characteristics & 0x400:
      char_meaning.append("IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP")
   if Characteristics & 0x800:
      char_meaning.append("IMAGE_FILE_NET_RUN_FROM_SWAP")
   if Characteristics & 0x1000:
      char_meaning.append("IMAGE_FILE_SYSTEM")
   if Characteristics & 0x2000:
      char_meaning.append("IMAGE_FILE_DLL")
   if Characteristics & 0x4000:
      char_meaning.append("IMAGE_FILE_UP_SYSTEM_ONLY")
   if Characteristics & 0x8000:
      char_meaning.append("IMAGE_FILE_BYTES_REVERSED_HI")

   return char_meaning

def parse_DllCharacteristics(DllCharacteristics):
   DllChar_meaning = list()

   if DllCharacteristics & 0x40:
      DllChar_meaning.append("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE")
   if DllCharacteristics & 0x80:
      DllChar_meaning.append("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY")
   if DllCharacteristics & 0x100:
      DllChar_meaning.append("IMAGE_DLLCHARACTERISTICS_NX_COMPAT")
   if DllCharacteristics & 0x200:
      DllChar_meaning.append("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION")
   if DllCharacteristics & 0x400:
      DllChar_meaning.append("IMAGE_DLLCHARACTERISTICS_NO_SEH")
   if DllCharacteristics & 0x800:
      DllChar_meaning.append("IMAGE_DLLCHARACTERISTICS_NO_BIND")
   if DllCharacteristics & 0x2000:
      DllChar_meaning.append("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER")
   if DllCharacteristics & 0x8000:
      DllChar_meaning.append("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE")

   return DllChar_meaning

def parse_file_header(pearray, e_lfanew):
   print("parsing File header...")

   Machine = int.from_bytes(pearray[e_lfanew + 4 : e_lfanew + 6], 'little')
   NumberOfSections = int.from_bytes(pearray[e_lfanew + 6 : e_lfanew + 8], 'little')
   TimeDateStamp = int.from_bytes(pearray[e_lfanew + 8 : e_lfanew + 12], 'little')
   PointerToSymbolTable = int.from_bytes(pearray[e_lfanew + 12 : e_lfanew + 16], 'little')  
   NumberOfSymbols = int.from_bytes(pearray[e_lfanew + 16 : e_lfanew + 20], 'little')
   SizeOfOptionalHeader = int.from_bytes(pearray[e_lfanew + 20 : e_lfanew + 22], 'little')
   Characteristics = int.from_bytes(pearray[e_lfanew + 22 : e_lfanew + 24], 'little')

   print(f"Machine :\t{Machine:x} ({e_get_machine(Machine)})")
   print(f"NumberOfSections :\t{NumberOfSections}")
   print(f"TimeDateStamp :\t0x{TimeDateStamp:x}")
   print(f"PointerToSymbolTable :\t0x{PointerToSymbolTable:x}")
   print(f"NumberOfSymbols :\t{NumberOfSymbols}")
   print(f"SizeOfOptionalHeader :\t{SizeOfOptionalHeader}")
   print(f"Characteristics :\t0x{Characteristics:x}")

   characteristics_list = parse_Characteristics(Characteristics)
   for char in characteristics_list:
      print(f"\t{char}")

   return (NumberOfSections, SizeOfOptionalHeader)

def parse_optional_header(pearray, e_lfanew, SizeOfOptionalHeader):
   print("parsing Optional header...")

   Magic = int.from_bytes(pearray[e_lfanew + 24 : e_lfanew + 26], 'little')

   MajorLinkerVersion = int.from_bytes(pearray[e_lfanew + 26 : e_lfanew + 27], 'little')
   MinorLinkerVersion = int.from_bytes(pearray[e_lfanew + 27 : e_lfanew + 28], 'little')
   SizeOfCode = int.from_bytes(pearray[e_lfanew + 28 : e_lfanew + 32], 'little')
   SizeOfInitializedData = int.from_bytes(pearray[e_lfanew + 32 : e_lfanew + 36], 'little')
   SizeOfUninitializedData = int.from_bytes(pearray[e_lfanew + 36 : e_lfanew + 40], 'little')
   AddressOfEntryPoint = int.from_bytes(pearray[e_lfanew + 40 : e_lfanew + 44], 'little')
   BaseOfCode = int.from_bytes(pearray[e_lfanew + 44 : e_lfanew + 48], 'little')
   ImageBase = int.from_bytes(pearray[e_lfanew + 48 : e_lfanew + 56], 'little')
   SectionAlignment = int.from_bytes(pearray[e_lfanew + 56 : e_lfanew + 60], 'little')
   FileAlignment = int.from_bytes(pearray[e_lfanew + 60 : e_lfanew + 64], 'little')
   MajorOperatingSystemVersion = int.from_bytes(pearray[e_lfanew + 64 : e_lfanew + 66], 'little')
   MinorOperatingSystemVersion = int.from_bytes(pearray[e_lfanew + 66 : e_lfanew + 68], 'little')
   MajorImageVersion = int.from_bytes(pearray[e_lfanew + 68 : e_lfanew + 70], 'little')
   MinorImageVersion = int.from_bytes(pearray[e_lfanew + 70 : e_lfanew + 72], 'little')
   MajorSubsystemVersion = int.from_bytes(pearray[e_lfanew + 72 : e_lfanew + 74], 'little')
   MinorSubsystemVersion = int.from_bytes(pearray[e_lfanew + 74 : e_lfanew + 76], 'little')
   Win32VersionValue = int.from_bytes(pearray[e_lfanew + 76 : e_lfanew + 80], 'little')
   SizeOfImage = int.from_bytes(pearray[e_lfanew + 80 : e_lfanew + 84], 'little')
   SizeOfHeaders = int.from_bytes(pearray[e_lfanew + 84 : e_lfanew + 88], 'little')
   CheckSum = int.from_bytes(pearray[e_lfanew + 88 : e_lfanew + 92], 'little')
   Subsystem = int.from_bytes(pearray[e_lfanew + 92 : e_lfanew + 94], 'little')
   DllCharacteristics = int.from_bytes(pearray[e_lfanew + 94 : e_lfanew + 96], 'little')
   SizeOfStackReserve = int.from_bytes(pearray[e_lfanew + 96 : e_lfanew + 104], 'little')
   SizeOfStackCommit = int.from_bytes(pearray[e_lfanew + 104 : e_lfanew + 112], 'little')
   SizeOfHeapReserve = int.from_bytes(pearray[e_lfanew + 112 : e_lfanew + 120], 'little')
   SizeOfHeapCommit = int.from_bytes(pearray[e_lfanew + 120 : e_lfanew + 128], 'little')
   LoaderFlags = int.from_bytes(pearray[e_lfanew + 128 : e_lfanew + 132], 'little')
   NumberOfRvaAndSizes = int.from_bytes(pearray[e_lfanew + 132 : e_lfanew + 136], 'little')

   print(f"Magic: {Magic:x} ({e_get_optional_magic(Magic)})")
   print(f"LinkerVersion: 0x{MajorLinkerVersion:x}{MinorLinkerVersion:x}")
   print(f"SizeOfCode: 0x{SizeOfCode:x} ({SizeOfCode} bytes)")
   print(f"SizeOfInitializedData: 0x{SizeOfInitializedData:x} ({SizeOfInitializedData} bytes)")
   print(f"SizeOfUninitializedData: 0x{SizeOfUninitializedData:x} ({SizeOfUninitializedData} bytes)")
   print(f"AddressOfEntryPoint: 0x{AddressOfEntryPoint:x}")
   print(f"BaseOfCode: 0x{BaseOfCode:x}")
   print(f"ImageBase: 0x{ImageBase:x}")
   print(f"SectionAlignment: 0x{SectionAlignment:x}")
   print(f"FileAlignment: 0x{FileAlignment:x}")
   print(f"MajorOperatingSystemVersion: 0x{MajorOperatingSystemVersion:x}")
   print(f"MinorOperatingSystemVersion: 0x{MinorOperatingSystemVersion:x}")
   print(f"MajorImageVersion: 0x{MajorImageVersion:x}")
   print(f"MinorImageVersion: 0x{MinorImageVersion:x}")
   print(f"MajorSubsystemVersion: 0x{MajorSubsystemVersion:x}")
   print(f"MinorSubsystemVersion: 0x{MinorSubsystemVersion:x}")
   print(f"Win32VersionValue: 0x{Win32VersionValue:x}")
   print(f"SizeOfImage: 0x{SizeOfImage:x} ({SizeOfImage} bytes)")
   print(f"SizeOfHeaders: 0x{SizeOfHeaders:x} ({SizeOfHeaders} bytes)")
   print(f"CheckSum: 0x{CheckSum:x}")
   print(f"Subsystem: 0x{Subsystem:x} ({e_get_sybsystem(Subsystem)})")

   DllChar_meaning = parse_DllCharacteristics(DllCharacteristics)
   for char in DllChar_meaning:
      print(f"\t{char}")

   print(f"SizeOfStackReserve: 0x{SizeOfStackReserve:x} ({SizeOfStackReserve})")
   print(f"SizeOfStackCommit: 0x{SizeOfStackCommit:x} ({SizeOfStackCommit})")
   print(f"SizeOfHeapReserve: 0x{SizeOfHeapReserve:x} ({SizeOfHeapReserve})")
   print(f"SizeOfHeapCommit: 0x{SizeOfHeapCommit:x} ({SizeOfHeapCommit})")
   print(f"LoaderFlags: 0x{LoaderFlags:x}")
   print(f"NumberOfRvaAndSizes: 0x{NumberOfRvaAndSizes:x}")

   return NumberOfRvaAndSizes

directory_name = ["Export Table", "Import Table", "Resource Table", "Exception Table", "Certificate Table", "Base Relocation Table", "Debug", "Architecture", "Global Ptr", "TLS Table", "Load Config Table", "Bound Import", "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"]

def parse_data_directories(pearray, e_lfanew, NumberOfRvaAndSizes):

   global verbose
   print("parsing data directories...")
   directory_list = list()

   offset = e_lfanew + 136

   for i in range(NumberOfRvaAndSizes):
   	VirtualAddress = int.from_bytes(pearray[offset + 8 * i : offset + 8 * i + 4], 'little')
   	Size = int.from_bytes(pearray[offset + 8 * i + 4 : offset + 8 * i + 8], 'little')

   	print(f"\tData Directory entry n°{i} at {(offset + (8 * i)):x} ({directory_name[i]}) - RVA: 0x{VirtualAddress:x} -> 0x{VirtualAddress + Size:x} (=> Size: 0x{Size:x})")
   	if verbose == True:
   		hexdump(pearray, VirtualAddress, Size)
   		
   	directory_list.append([VirtualAddress, directory_name[i], Size])

   return ((offset + 8 * NumberOfRvaAndSizes), directory_list)

def parse_SectionHeaderCharacteristics(Characteristics):
   SectionChar_meaning = list()

   if Characteristics & 0x00000008:
      SectionChar_meaning.append("IMAGE_SCN_TYPE_NO_PAD")
   if Characteristics & 0x00000020:
      SectionChar_meaning.append("IMAGE_SCN_CNT_CODE")
   if Characteristics & 0x00000040:
      SectionChar_meaning.append("IMAGE_SCN_CNT_INITIALIZED_DATA")
   if Characteristics & 0x00000080:
      SectionChar_meaning.append("IMAGE_SCN_CNT_UNINITIALIZED_DATA")
   if Characteristics & 0x00000200:
      SectionChar_meaning.append("IMAGE_SCN_LNK_INFO")
   if Characteristics & 0x00000800:
      SectionChar_meaning.append("IMAGE_SCN_LNK_REMOVE")
   if Characteristics & 0x00001000:
      SectionChar_meaning.append("IMAGE_SCN_LNK_COMDAT")
   if Characteristics & 0x00004000:
      SectionChar_meaning.append("IMAGE_SCN_NO_DEFER_SPEC_EXC")
   if Characteristics & 0x00008000:
      SectionChar_meaning.append("IMAGE_SCN_GPREL")
   if Characteristics & 0x02000000:
      SectionChar_meaning.append("IMAGE_SCN_MEM_DISCARDABLE")
   if Characteristics & 0x04000000:
      SectionChar_meaning.append("IMAGE_SCN_MEM_NOT_CACHED")
   if Characteristics & 0x08000000:
      SectionChar_meaning.append("IMAGE_SCN_MEM_NOT_PAGED")
   if Characteristics & 0x10000000:
      SectionChar_meaning.append("IMAGE_SCN_MEM_SHARED")
   if Characteristics & 0x20000000:
      SectionChar_meaning.append("IMAGE_SCN_MEM_EXECUTE")
   if Characteristics & 0x40000000:
      SectionChar_meaning.append("IMAGE_SCN_MEM_READ")
   if Characteristics & 0x80000000:
      SectionChar_meaning.append("IMAGE_SCN_MEM_WRITE")

   return SectionChar_meaning

def parse_section_headers(pearray, section_headers_offset, NumberOfSections):
   print("parsing section headers...")

   section_list = list()

   for i in range(NumberOfSections):
   	Name = pearray[section_headers_offset + i * 40 :  section_headers_offset + i * 40 + 8]
   	VirtualSize = int.from_bytes(pearray[section_headers_offset + i * 40 + 8 : section_headers_offset + i * 40 + 12], 'little')
   	VirtualAddress = int.from_bytes(pearray[section_headers_offset + i * 40 + 12 : section_headers_offset + i * 40 + 16], 'little')
   	SizeOfRawData = int.from_bytes(pearray[section_headers_offset + i * 40 + 16 : section_headers_offset + i * 40 + 20], 'little')
   	PointerToRawData = int.from_bytes(pearray[section_headers_offset + i * 40 + 20 : section_headers_offset + i * 40 + 24], 'little')
   	PointerToRelocations = int.from_bytes(pearray[section_headers_offset + i * 40 + 24 : section_headers_offset + i * 40 + 28], 'little')
   	PointerToLinenumbers = int.from_bytes(pearray[section_headers_offset + i * 40 + 28 : section_headers_offset + i * 40 + 32], 'little')
   	NumberOfRelocations = int.from_bytes(pearray[section_headers_offset + i * 40 + 32 : section_headers_offset + i * 40 + 34], 'little')
   	NumberOfLinenumbers = int.from_bytes(pearray[section_headers_offset + i * 40 + 34 : section_headers_offset + i * 40 + 36], 'little')
   	Characteristics = int.from_bytes(pearray[section_headers_offset + i * 40 + 36 : section_headers_offset + i * 40 + 40], 'little')

   	print(f"section n°{i}:")
   	print(f"\tName: {Name}")
   	print(f"\tVirtualSize: 0x{VirtualSize:x}")
   	print(f"\tVirtualAddress: 0x{VirtualAddress:x}")
   	print(f"\tSizeOfRawData: 0x{SizeOfRawData:x}")
   	print(f"\tPointerToRawData: 0x{PointerToRawData:x}")
   	print(f"\tPointerToRelocations: 0x{PointerToRelocations:x}")
   	print(f"\tNumberOfRelocations: 0x{NumberOfRelocations:x}")
   	print(f"\tNumberOfRelocations: 0x{NumberOfRelocations:x}")
   	print(f"\tNumberOfLinenumbers: 0x{NumberOfLinenumbers:x}")
   	print(f"\tCharacteristics: 0x{Characteristics:x} ({parse_SectionHeaderCharacteristics(Characteristics)})")

   	section_list.append([PointerToRawData, Name])

   return section_list

def parse_nt_header(pearray, e_lfanew):
   print("parsing NT header...")

   Signature = pearray[e_lfanew : e_lfanew + 4]

   if Signature != b'PE\x00\x00':
      print("Invalid NT header !")
      return -1

   (NumberOfSections, SizeOfOptionalHeader) = parse_file_header(pearray, e_lfanew)
   NumberOfRvaAndSizes = parse_optional_header(pearray, e_lfanew, SizeOfOptionalHeader)

   (section_headers_offset, directory_list) = parse_data_directories(pearray, e_lfanew, NumberOfRvaAndSizes)
   section_list = parse_section_headers(pearray, section_headers_offset, NumberOfSections)

   m = len(section_list)
   n = len(directory_list)
   
   for i in range(m):
   	
   	curr_section_addr = section_list[i][0]
   	print(f"section n°{i}: {section_list[i][1]} 0x{curr_section_addr:x}")
   	
   	if i < m - 1:
	   	next_section_addr = section_list[i + 1][0]
   	else:
   		next_section_addr = 9999999999999999999999
   
   	for j in range(n):
   		curr_directory_addr = directory_list[j][0]
   		
   		if curr_directory_addr >= curr_section_addr and curr_directory_addr < next_section_addr:
   			print(f"\tdirectory n°{j} {directory_list[j][1]} 0x{curr_directory_addr:x}")
   		
   parse_import_directory(pearray, directory_list[1][0], directory_list[1][2])
   parse_iat_directory(pearray, directory_list[12][0], directory_list[12][2])
   parse_export_directory(pearray, directory_list[0][0], directory_list[0][2])

def read_string_at(array, offset):

	index = offset
	c = array[index]
	while c != 0:
		index += 1
		c = array[index]

	name = array[offset:index]
	return str(name)

def parse_import_directory(pearray, import_table_offset, import_table_size):
	print("parsing import directory table...")

	print(f"Import Directory offset 0x{import_table_offset:x} size 0x{import_table_size:x}")
	
	offset = import_table_offset

	for i in range(99999999999):

		offset = import_table_offset + i * 20
	
		OriginalFirstThunk = int.from_bytes(pearray[offset : offset + 4], 'little')
		TimeDateStamp = int.from_bytes(pearray[offset + 4 : offset + 8], 'little')
		ForwarderChain = int.from_bytes(pearray[offset + 8 : offset + 12], 'little')
		Name = int.from_bytes(pearray[offset + 12 : offset + 16], 'little')
		FirstThunk = int.from_bytes(pearray[offset + 16 : offset + 20], 'little')
		if OriginalFirstThunk == 0:
			break

		DllName = read_string_at(pearray, Name)

		print(f"\tentry n°{i} in Import Directory:")
		print(f"\t\tOriginalFirstThunk: 0x{OriginalFirstThunk:x}")
		print(f"\t\tTimeDateStamp: 0x{TimeDateStamp:x}")
		print(f"\t\tForwarderChain: 0x{ForwarderChain:x}")
		print(f"\t\tFirstThunk: 0x{FirstThunk:x}")
		print(f"\t\tName at 0x{Name:x} is {DllName}")
		
		parse_ilt_or_iat(pearray, OriginalFirstThunk, DllName, False)
		parse_ilt_or_iat(pearray, FirstThunk, DllName, True)

def parse_iat_directory(pearray, iat_offset, iat_size):
	print("parsing IAT directory...")
	print(f"IAT directory goes from 0x{iat_offset:x} to 0x{iat_size + iat_offset:x} (0x{iat_size:x} bytes)")

def parse_ilt_or_iat(pearray, FirstThunk, DllName, is_iat):
	if is_iat is True:
		print(f"\tparsing IAT table for DLL {DllName} at 0x{FirstThunk:x}...")
	else:
		print(f"\tparsing ILT table for DLL {DllName} at 0x{FirstThunk:x}...")

	for i in range(99999999999):	

		iat_entry = int.from_bytes(pearray[FirstThunk + 8 * i: FirstThunk + 8 * i + 8], 'little')
		if iat_entry == 0:
			break
			
		if iat_entry & 0x8000000000000000:
			ordinal = iat_entry & 0x7fffffffffffffff

			print("\t\timport by ordinal !")
			print(f"\t\tiat_entry ordinal: {ordinal}")
		else:
			hintNameRVA = iat_entry
			hint = int.from_bytes(pearray[hintNameRVA : hintNameRVA + 2], 'little')
			name = read_string_at(pearray, hintNameRVA + 2)

			print("\t\timport by name !")
			print(f"\t\thintNameRVA : 0x{hintNameRVA:x}")
			print(f"\t\tiat_entry hint : 0x{hint:x}")
			print(f"\t\tiat_entry name : {name} (function n°{i})")

def parse_export_directory(pearray, export_table_offset, export_table_size):
	print("parsing export directory table...")

	print(f"Export Directory offset 0x{export_table_offset:x} size 0x{export_table_size:x}")
	
	offset = export_table_offset

	ExportFlag = int.from_bytes(pearray[offset : offset + 4], 'little')
	TimeDateStamp = int.from_bytes(pearray[offset + 4 : offset + 8], 'little')
	MajorVersion =  int.from_bytes(pearray[offset + 8 : offset + 10], 'little')
	MinorVersion =  int.from_bytes(pearray[offset + 10 : offset + 12], 'little')
	DllNameRVA = int.from_bytes(pearray[offset + 12 : offset + 16], 'little')
	DllName = read_string_at(pearray, DllNameRVA)
	OrdinalBase = int.from_bytes(pearray[offset + 16 : offset + 20], 'little')
	AddressTableEntries = int.from_bytes(pearray[offset + 20 : offset + 24], 'little')
	NumberOfNamePointers = int.from_bytes(pearray[offset + 24 : offset + 28], 'little')
	ExportTableRVA = int.from_bytes(pearray[offset + 28 : offset + 32], 'little')
	NamePointerRVA = int.from_bytes(pearray[offset + 32 : offset + 36], 'little')
	OrdinalTableRVA = int.from_bytes(pearray[offset + 36 : offset + 40], 'little')

	print(f"ExportFlag: 0x{ExportFlag:x}")
	print(f"TimeDateStamp: 0x{TimeDateStamp:x}")
	print(f"Version 0x{MajorVersion:x}{MinorVersion:x}")
	print(f"DLLNameRVA: 0x{DllNameRVA}")
	print(f"DLLName: {DllName}")
	print(f"Ordinal Base: {OrdinalBase}")
	print(f"Number of functions: {AddressTableEntries} (0x{AddressTableEntries:x})")
	print(f"Number of Names: {NumberOfNamePointers} (0x{NumberOfNamePointers:x})")
	print(f"ExportTableRVA: 0x{ExportTableRVA:x}")
	print(f"NamePointerRVA: 0x{NamePointerRVA:x}")
	print(f"OrdinalTableRVA: 0x{OrdinalTableRVA:x}")
	
	parse_export_table(pearray, OrdinalBase, ExportTableRVA, NamePointerRVA, OrdinalTableRVA, AddressTableEntries, NumberOfNamePointers)

def parse_export_table(pearray, OrdinalBase, ExportTableRVA, NamePointerRVA, OrdinalTableRVA, AddressTableEntries, NumberOfNamePointers):
	print("parsing the export table...")
	
	for i in range(AddressTableEntries):

		functionRVA = int.from_bytes(pearray[ExportTableRVA + 4 * i : ExportTableRVA + 4 * i + 4], 'little')
		functionNameRVA = int.from_bytes(pearray[NamePointerRVA + 4 * i : NamePointerRVA + 4 * i + 4], 'little')
		functionName = read_string_at(pearray, functionNameRVA)
		ordinal = int.from_bytes(pearray[OrdinalTableRVA + 2 * i : OrdinalTableRVA + 2 * i + 2], 'little')
		ordinal = ordinal + OrdinalBase

		print(f"Function n°{ordinal} / 0x{ordinal:x} ({functionName}) is at 0x{functionRVA:x}") 

def parse_msdos_header(pearray):
   print("parsing MS-DOS header...")

   e_magic = pearray[0 : 2]
	
   if e_magic != b'MZ':
      print("Invalid MS-DOS header !")
      return -1

   e_lfanew = int.from_bytes(pearray[0x3c : 0x3c + 4], 'little')
   return e_lfanew

def parse_pe(pearray):
	e_lfanew = parse_msdos_header(pearray)
	print(f"PE header is at offset {e_lfanew}")
	
	parse_nt_header(pearray, e_lfanew)

def main(args):
   pepath = args[1]

   global verbose
   verbose = False

   if len(args) == 3 and args[2] == "-v":
   	verbose = True

   pesize = os.stat(pepath).st_size
    
   with open(pepath, "rb") as fd:
      pearray = fd.read(pesize)

   parse_pe(pearray)

if __name__ == '__main__':
   main(sys.argv)
