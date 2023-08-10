
/* NtAlpcAcceptConnectPort Params
 * arg0 OUT PHANDLE PortHandle
 * arg1 IN PUNICODE_STRING PortName
 * arg2 IN POBJECT_ATTRIBUTES ObjectAttributes
 * arg3 OPTIONAL PALPC_PORT_ATTRIBUTES PortAttributes
 * arg4 IN ULONG Flags
 * TODO(will): Fix this
 */

::NtAlpcConnectPort:entry
{
    this->us = (PUNICODE_STRING)arg1;
    this->val = wstr2str(copyin(this->us->Buffer, this->us->Length) / 2);
    printf("%s (%d) NtAlpcConnectPort %s called\n", execname, pid, this->val);
}

/* NtAlpcAcceptConnectPort Params
 * arg0 _Out_ PHANDLE  	PortHandle,
 * arg1 _In_ HANDLE  	ConnectionPortHandle,
 * arg2 _In_ ULONG  	Flags,
 * arg3 _In_opt_ POBJECT_ATTRIBUTES  	ObjectAttributes,
 * arg4 _In_opt_ PALPC_PORT_ATTRIBUTES  	PortAttributes,
 * arg5 _In_opt_ PVOID  	PortContext,
 * arg6 _In_reads_bytes_(ConnectionRequest->u1.s1.TotalLength) PPORT_MESSAGE  	ConnectionRequest,
 * arg7 _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES  	ConnectionMessageAttributes,
 * arg8 _In_ BOOLEAN 
 */
::NtAlpcAcceptConnectPort:entry
{
  printf("%s (%d) NtAlpcAcceptConnectPort\n", execname, pid);
}
