First we need to add environment variable HASHVALUE to our project, because if we change the hash from the binary, we are changing the integrity.
Instead we can update the environment variable without changing integrity. This method, is compiled to the binary, runtime.
![Pasted image 20230813185431.png](Pasted%20image%2020230813185431.png)

after that we define macros for getting the hash.

````c
#define STRINGIZER(arg)     #arg
#define STR_VALUE(arg)      STRINGIZER(arg)
#define HASH				STR_VALUE(HASHVALUE)
````

And custom hash function

````c
UINT64 HashStringJenkinsOneAtATime32BitA(_In_ BYTE *String,ULONG Length)
{
	ULONG Index = 0;
	UINT64 Hash = 0;
	
	printf("0x%p\n", Length);
	while (Index != Length)
	{
		Hash += *(String +Index);
		Index++;
		Hash += Hash << 7;
		Hash ^= Hash >> 6;
	}
	printf("Hash Created\n");
	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}
````

We can get file integrity from .text section and detect software breakpoints easily with this kind of function

````c
BOOL FileIntegrityCheck() {

	PBYTE textSection = NULL;
	ULONG textSectionSize = NULL;
	// getting the PEB structure
#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif
	PBYTE baseAddr = pPeb->ImageBase;
	printf("base addr: 0x%p\n", baseAddr);
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)baseAddr;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Magic Bytes are not correct");
	}

	// Pointer to the structure
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(baseAddr + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		printf("Getting NT_SIGNATURE FAILED");
		return -1;
	}

	IMAGE_FILE_HEADER	ImgFileHdr = pImgNtHdrs->FileHeader;
	DWORD sectionCount = ImgFileHdr.NumberOfSections;

	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
	if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		return -1;
	}

	IMAGE_DATA_DIRECTORY ExpDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	IMAGE_DATA_DIRECTORY ImportDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	printf("Export table is at 0x%p\n", ((PBYTE)baseAddr + ExpDataDir.VirtualAddress));
	printf("Import table is at 0x%p\n", ((PBYTE)baseAddr + ImportDir.VirtualAddress));
	PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));

	// pImgSectionHdr is now a pointer to first section
	for (size_t i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		LPSTR name = pImgSectionHdr->Name;
		printf("%s", name);
		if (strcmp(name, ".text") == 0) {
			printf("################# Section %d ###############\n", i);
			printf("Section name %s\n", pImgSectionHdr->Name);
			printf("Section address 0x%p\n", ((PBYTE)baseAddr + pImgSectionHdr->VirtualAddress));
			textSection = ((PBYTE)baseAddr + pImgSectionHdr->VirtualAddress); // Virtual Address of section
			textSectionSize = pImgSectionHdr->Misc.VirtualSize; // Size of section
			printf("Size = 0x%p\n", textSectionSize);
			printf("Number of Relocations %d\n", pImgSectionHdr->NumberOfRelocations);
			break;
		}
		pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));
		// pImgSectionHdr is now a pointer to next section 
	}
	printf("section is at 0x%p\n", textSection);
	printf("textSectionSize %u\n",textSectionSize);
	UINT64 hash = HashStringJenkinsOneAtATime32BitA(textSection, textSectionSize);
	LPSTR hashCheck = HASH;
	printf("%s\n", hashCheck);
	LPSTR checksum = HeapAlloc(GetProcessHeap(),PAGE_READWRITE,34);
	sprintf(checksum,"0x%p", hash);
	printf("checksum: %s\n", checksum);
	if (strcmp(checksum ,hashCheck)!=0) {
		printf("File integrity failed\n");
		printf("0x%p\n", hash);
		return FALSE;
	}
	printf("0x%p\n", hash);
	getchar();

	return TRUE;
}
````
