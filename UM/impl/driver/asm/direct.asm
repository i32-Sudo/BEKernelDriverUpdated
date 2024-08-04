.code 

direct_device_control PROC

	mov r10, rcx
	mov eax, 7
	syscall
	ret

direct_device_control ENDP

END