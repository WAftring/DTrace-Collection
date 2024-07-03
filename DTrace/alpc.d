#pragma D option quiet

/* NtAlpcConnectPort Params
 * arg0 OUT PHANDLE PortHandle
 * arg1 IN PUNICODE_STRING PortName
 * arg2 IN POBJECT_ATTRIBUTES ObjectAttributes
 * arg3 OPTIONAL PALPC_PORT_ATTRIBUTES PortAttributes
 * arg4 IN ULONG Flags
 */

syscall::NtAlpcConnectPort:entry
{
  this->PortName = (nt`UNICODE_STRING*)copyin(arg1, sizeof(nt`UNICODE_STRING));
  this->wBuffer = (uint16_t*) copyin((uintptr_t)this->PortName->Buffer, this->PortName->Length);
  this->aBuffer = wstr2str((wchar_t*)this->wBuffer, this->PortName->Length / 2);
  printf("%s (%d) NtAlpcConnectPort %s called\n", execname, pid, this->aBuffer);
}
