/*
 * Minimal native comparison launcher for the Astra AppContainer PoC.
 *
 * This is an independent diagnostic. It does not include or connect to
 * OpenJarvis, RLMWorker, ToolExecutor, or any LLM/provider code.
 */

#define UNICODE
#define _UNICODE
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <sddl.h>
#include <userenv.h>
#include <stdio.h>
#include <stddef.h>
#include <wchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")

#define NATIVE_CRASH_CODE 0xD1

static void print_hr(const char *name, HRESULT hr)
{
    printf("%s_HRESULT=0x%08lX\n", name, (unsigned long)hr);
}

static BOOL append_environment_entry(
    wchar_t **cursor,
    size_t *remaining,
    LPCWSTR name,
    LPCWSTR value)
{
    int written;

    written = _snwprintf_s(
        *cursor,
        *remaining,
        _TRUNCATE,
        L"%ls=%ls",
        name,
        value);
    if (written < 0 || (size_t)written + 1 > *remaining) {
        return FALSE;
    }

    *cursor += written + 1;
    *remaining -= (size_t)written + 1;
    return TRUE;
}

static BOOL build_environment_block(
    wchar_t *buffer,
    size_t capacity,
    LPCWSTR current_directory,
    BOOL include_drive_entry)
{
    wchar_t *cursor = buffer;
    size_t remaining = capacity;

    /* Sorted case-insensitively, including the special current-drive entry. */
    if ((include_drive_entry
            && !append_environment_entry(&cursor, &remaining, L"=C:", current_directory))
        || !append_environment_entry(&cursor, &remaining, L"PATH", L"C:\\Windows\\System32")
        || !append_environment_entry(&cursor, &remaining, L"PYTHONHOME", L"C:\\Windows\\System32")
        || !append_environment_entry(&cursor, &remaining, L"PYTHONNOUSERSITE", L"1")
        || !append_environment_entry(&cursor, &remaining, L"SystemRoot", L"C:\\Windows")
        || !append_environment_entry(&cursor, &remaining, L"WINDIR", L"C:\\Windows")) {
        return FALSE;
    }

    if (remaining < 1) {
        return FALSE;
    }
    *cursor = L'\0';
    return TRUE;
}

static BOOL configure_job(HANDLE job)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;

    ZeroMemory(&limits, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    limits.BasicLimitInformation.ActiveProcessLimit = 4;

    return SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        &limits,
        (DWORD)sizeof(limits));
}

int wmain(int argc, wchar_t **argv)
{
    const wchar_t current_directory[] = L"C:\\Windows\\System32";
    const wchar_t application_name[] = L"C:\\Windows\\System32\\cmd.exe";
    wchar_t command_line[] = L"\"C:\\Windows\\System32\\cmd.exe\" /d /c exit 0";
    wchar_t environment[2048];
    wchar_t profile_name[64];
    PSID app_container_sid = NULL;
    LPWSTR sid_string = NULL;
    SIZE_T attribute_size = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    SECURITY_CAPABILITIES security_capabilities;
    STARTUPINFOEXW startup_info;
    PROCESS_INFORMATION process_info;
    HANDLE job = NULL;
    HRESULT hr;
    BOOL created = FALSE;
    BOOL process_in_job = FALSE;
    BOOL job_query_ok = FALSE;
    BOOL cleanup_ok = TRUE;
    DWORD immediate_create_error = ERROR_SUCCESS;
    DWORD wait_result = WAIT_FAILED;
    DWORD exit_code = STILL_ACTIVE;
    BOOL include_drive_entry = TRUE;
    BOOL app_name_is_null = FALSE;
    BOOL current_directory_is_null = FALSE;
    BOOL create_suspended = TRUE;
    DWORD creation_flags;
    int return_code = 1;

    if (argc > 2
        || (argc == 2
            && wcscmp(argv[1], L"no-drive") != 0
            && wcscmp(argv[1], L"no-appname") != 0
            && wcscmp(argv[1], L"no-cwd") != 0
            && wcscmp(argv[1], L"no-suspend") != 0)) {
        printf("USAGE= native_appcontainer_launcher.exe [no-drive|no-appname|no-cwd|no-suspend]\n");
        return 2;
    }
    if (argc == 2 && wcscmp(argv[1], L"no-drive") == 0) {
        include_drive_entry = FALSE;
    }
    if (argc == 2 && wcscmp(argv[1], L"no-appname") == 0) {
        app_name_is_null = TRUE;
    }
    if (argc == 2 && wcscmp(argv[1], L"no-cwd") == 0) {
        current_directory_is_null = TRUE;
    }
    if (argc == 2 && wcscmp(argv[1], L"no-suspend") == 0) {
        create_suspended = FALSE;
    }

    creation_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
    if (create_suspended) {
        creation_flags |= CREATE_SUSPENDED;
    }

    ZeroMemory(&security_capabilities, sizeof(security_capabilities));
    ZeroMemory(&startup_info, sizeof(startup_info));
    ZeroMemory(&process_info, sizeof(process_info));

    _snwprintf_s(
        profile_name,
        _countof(profile_name),
        _TRUNCATE,
        L"AstraNativePoc.%lu.%llu",
        (unsigned long)GetCurrentProcessId(),
        (unsigned long long)(GetTickCount64() % 100000000ULL));

    printf("TEST=native_appcontainer_create\n");
    printf("EXPECTED=one benign AppContainer process creation attempt\n");
    printf("ABI.pointer_size=%zu\n", sizeof(void *));
    printf("ABI.SECURITY_CAPABILITIES.size=%zu offsets=%zu,%zu,%zu,%zu\n",
        sizeof(SECURITY_CAPABILITIES),
        offsetof(SECURITY_CAPABILITIES, AppContainerSid),
        offsetof(SECURITY_CAPABILITIES, Capabilities),
        offsetof(SECURITY_CAPABILITIES, CapabilityCount),
        offsetof(SECURITY_CAPABILITIES, Reserved));
    printf("ABI.STARTUPINFO.size=%zu STARTUPINFOEX.size=%zu offset_attribute_list=%zu\n",
        sizeof(STARTUPINFO),
        sizeof(STARTUPINFOEX),
        offsetof(STARTUPINFOEX, lpAttributeList));
    printf("ABI.PROCESS_INFORMATION.size=%zu\n", sizeof(PROCESS_INFORMATION));
    printf("CONFIG.capability_count=0 network_capability=0 inherit_handles=0\n");
    printf("CONFIG.flags=0x%08lX\n", (unsigned long)creation_flags);
    printf("CONFIG.environment_variant=%s\n",
        include_drive_entry ? "full" : "no-drive");
    printf("CONFIG.application_name=%s\n",
        app_name_is_null ? "NULL" : "explicit");
    printf("CONFIG.current_directory=%s\n",
        current_directory_is_null ? "NULL" : "explicit");
    printf("CONFIG.create_suspended=%s\n",
        create_suspended ? "TRUE" : "FALSE");
    printf("CONFIG.environment_keys=%s\n",
        include_drive_entry
            ? "=C:,PATH,PYTHONHOME,PYTHONNOUSERSITE,SystemRoot,WINDIR"
            : "PATH,PYTHONHOME,PYTHONNOUSERSITE,SystemRoot,WINDIR");

    if (!build_environment_block(
        environment,
        _countof(environment),
        current_directory,
        include_drive_entry)) {
        printf("FAIL=environment_block_construction\n");
        goto cleanup;
    }

    hr = CreateAppContainerProfile(
        profile_name,
        L"Astra Native Proof",
        L"Temporary native AppContainer launch diagnostic",
        NULL,
        0,
        &app_container_sid);
    if (FAILED(hr)) {
        print_hr("CreateAppContainerProfile", hr);
        goto cleanup;
    }
    printf("CreateAppContainerProfile=SUCCESS\n");

    if (ConvertSidToStringSidW(app_container_sid, &sid_string)) {
        printf("AppContainerSid=present\n");
        LocalFree(sid_string);
        sid_string = NULL;
    } else {
        printf("ConvertSidToStringSidW_ERROR=%lu\n", (unsigned long)GetLastError());
    }

    SetLastError(ERROR_SUCCESS);
    InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || attribute_size == 0) {
        printf("InitializeProcThreadAttributeList_size_ERROR=%lu\n",
            (unsigned long)GetLastError());
        goto cleanup;
    }

    attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(),
        0,
        attribute_size);
    if (attributes == NULL) {
        printf("HeapAlloc_ERROR=%lu\n", (unsigned long)GetLastError());
        goto cleanup;
    }

    if (!InitializeProcThreadAttributeList(
        attributes,
        1,
        0,
        &attribute_size)) {
        printf("InitializeProcThreadAttributeList_ERROR=%lu\n",
            (unsigned long)GetLastError());
        goto cleanup;
    }

    security_capabilities.AppContainerSid = app_container_sid;
    security_capabilities.Capabilities = NULL;
    security_capabilities.CapabilityCount = 0;
    security_capabilities.Reserved = 0;
    if (!UpdateProcThreadAttribute(
        attributes,
        0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        &security_capabilities,
        sizeof(security_capabilities),
        NULL,
        NULL)) {
        printf("UpdateProcThreadAttribute_ERROR=%lu\n",
            (unsigned long)GetLastError());
        goto cleanup;
    }

    startup_info.StartupInfo.cb = sizeof(startup_info);
    startup_info.lpAttributeList = attributes;

    job = CreateJobObjectW(NULL, NULL);
    if (job == NULL) {
        printf("CreateJobObjectW_ERROR=%lu\n", (unsigned long)GetLastError());
        goto cleanup;
    }
    if (!configure_job(job)) {
        printf("SetInformationJobObject_ERROR=%lu\n",
            (unsigned long)GetLastError());
        goto cleanup;
    }

    SetLastError(ERROR_SUCCESS);
    created = CreateProcessW(
        app_name_is_null ? NULL : application_name,
        command_line,
        NULL,
        NULL,
        FALSE,
        creation_flags,
        environment,
        current_directory_is_null ? NULL : current_directory,
        (LPSTARTUPINFOW)&startup_info,
        &process_info);
    immediate_create_error = created ? ERROR_SUCCESS : GetLastError();

    printf("CreateProcessW_RETURN=%s\n", created ? "TRUE" : "FALSE");
    printf("CreateProcessW_IMMEDIATE_GETLASTERROR=%lu\n",
        (unsigned long)immediate_create_error);

    if (!created) {
        goto cleanup;
    }

    if (!AssignProcessToJobObject(job, process_info.hProcess)) {
        printf("AssignProcessToJobObject_ERROR=%lu\n",
            (unsigned long)GetLastError());
        TerminateProcess(process_info.hProcess, NATIVE_CRASH_CODE);
        WaitForSingleObject(process_info.hProcess, 5000);
        goto cleanup;
    }
    if (create_suspended && !ResumeThread(process_info.hThread)) {
        printf("ResumeThread_ERROR=%lu\n", (unsigned long)GetLastError());
        TerminateJobObject(job, NATIVE_CRASH_CODE);
        goto cleanup;
    }

    wait_result = WaitForSingleObject(process_info.hProcess, 10000);
    if (wait_result == WAIT_TIMEOUT) {
        printf("WAIT_RESULT=TIMEOUT\n");
        TerminateJobObject(job, NATIVE_CRASH_CODE);
        WaitForSingleObject(process_info.hProcess, 5000);
        goto cleanup;
    }
    if (wait_result != WAIT_OBJECT_0) {
        printf("WAIT_RESULT_ERROR=%lu\n", (unsigned long)GetLastError());
        goto cleanup;
    }

    if (!GetExitCodeProcess(process_info.hProcess, &exit_code)) {
        printf("GetExitCodeProcess_ERROR=%lu\n",
            (unsigned long)GetLastError());
        goto cleanup;
    }
    job_query_ok = IsProcessInJob(process_info.hProcess, job, &process_in_job);
    printf("CHILD_EXIT_CODE=%lu\n", (unsigned long)exit_code);
    printf("CHILD_JOB_QUERY=%s\n",
        job_query_ok && process_in_job ? "TRUE" : "FALSE");
    return_code = exit_code == 0 && job_query_ok && process_in_job ? 0 : 1;

cleanup:
    if (sid_string != NULL) {
        LocalFree(sid_string);
    }
    if (process_info.hThread != NULL) {
        CloseHandle(process_info.hThread);
    }
    if (process_info.hProcess != NULL) {
        CloseHandle(process_info.hProcess);
    }
    if (job != NULL && !CloseHandle(job)) {
        cleanup_ok = FALSE;
        printf("CloseHandle_job_ERROR=%lu\n", (unsigned long)GetLastError());
    }
    if (attributes != NULL) {
        DeleteProcThreadAttributeList(attributes);
        if (!HeapFree(GetProcessHeap(), 0, attributes)) {
            cleanup_ok = FALSE;
            printf("HeapFree_attributes_ERROR=%lu\n",
                (unsigned long)GetLastError());
        }
    }
    if (app_container_sid != NULL) {
        hr = DeleteAppContainerProfile(profile_name);
        if (FAILED(hr)) {
            cleanup_ok = FALSE;
            print_hr("DeleteAppContainerProfile", hr);
        }
        FreeSid(app_container_sid);
    }
    printf("CLEANUP=%s\n", cleanup_ok ? "PASS" : "FAIL");
    if (!cleanup_ok) {
        return_code = 1;
    }
    return return_code;
}
