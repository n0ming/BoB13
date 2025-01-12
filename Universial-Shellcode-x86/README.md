# Universial-Shellcode-x86

## 1. 개요

이 문서는 `WinExec`를 사용하여 `Hello.exe`를 실행하는 방법을 설명합니다. 기존의 `CreateProcessA` 함수와 달리 `WinExec` 함수는 보다 간단한 인자 구조를 가지고 있으며, 이에 따라 기존 코드를 변경하는 방법을 설명합니다.

## 2. Compute_Hash 함수 호출 이후 수정 사항

기존 코드에서는 `CreateProcessA` 함수 호출 후 `add` 명령어를 사용하여 값을 더해주고 있었습니다. 그러나 `WinExec`는 `CreateProcessA`와 달리 0x8 크기이므로, `0x10`에서 `0x8`로 수정해야 합니다.

```assembly
add esp, 0x8 ; 기존 0x10에서 0x8로 수정
```

## 3. WinExec 함수 
그리고 WinExec함수는 다음 아래의 형태를 구성하고 있습니다. 
```assembly
    UINT WINAPI WinExec(
      _In_ LPCSTR lpCmdLine,
      _In_ UINT   uCmdShow
    );
```
IpCmdLine은 Hello.exe의 주소가 들어가야하며, uCmdShow는 SW_SHOWNORMAL으로 1을 넣었습니다. 이에 맞춰 작성한 코드가 아래입니다.
```assembly
    push 1 // SW_SHOWNORMAL
    push DWORD PTR[ebp - 0x3C] // lpCmdLine
```
##4. CreateProcessA
그렇기에 CreateProcessA의 인자로 작성한 아래 코드를 모두 WinExec함수 인자로 바꿔줘야 합니다.
아래가 CreateProcessA의 형태입니다.
```assembly
    BOOL CreateProcessA(
      [in, optional]      LPCSTR                lpApplicationName,
      [in, out, optional] LPSTR                 lpCommandLine,
      [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
      [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
      [in]                BOOL                  bInheritHandles,
      [in]                DWORD                 dwCreationFlags,
      [in, optional]      LPVOID                lpEnvironment,
      [in, optional]      LPCSTR                lpCurrentDirectory,
      [in]                LPSTARTUPINFOA        lpStartupInfo,
      [out]               LPPROCESS_INFORMATION lpProcessInformation
    );
```
그 아래가 바로 멘토님의 코드에서 CreateProcessA의 인자 관련 코드입니다.
```assembly
    mov DWORD PTR [ebp-0x48], 0x44 //StartupInfo cb
    lea eax, [ebp-0x48]  //eax: StartupInfo addr
    push eax //pProcessInfo
    push eax //pStartupInfo
    push 0x0 //starting directory
    push 0x0 //Environment block
    push 0x0 //Create flags
    push 0x0 //bInherit Handle
    push 0x0 //lpThreadAttribute
    push 0x0 //lpProcessAttribute
    push DWORD PTR [ebp-0x4C] //lpCommandLine
    push 0x0 //lpApplicationName
```

번외로 저는 기존의 공간 할당한 크기값을 좀더 줄여서 진행하여 0x40을 마지막에 다시 add해주었습니다.
```assembly
    add esp, 0x40
```
# 실행 결과
![스크린샷 2024-08-15 025421](https://github.com/user-attachments/assets/e1c63411-2d07-4f0f-a219-e1d1f716bab0)
