using Grpc.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace Things.Services
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly WorkerSettings _settings;

        private class SessionInfo
        {
            public int SessionId { get; set; }
            public string UserName { get; set; }
            public string DesktopName { get; set; }
        }

        public Worker(ILogger<Worker> logger, IOptions<WorkerSettings> settings)
        {
            _logger = logger;
            _settings = settings.Value;
        }

        private void LaunchProcessWithSessionPrivileges(SessionInfo sessionInfo, string commandLine)
        {
            uint processId = GetFirstProcessIdFromUserSession(sessionInfo);

            if (StartProcessAsUser(processId, commandLine)) throw new InvalidOperationException($"Failed to start process as user {sessionInfo.UserName} in session {sessionInfo.SessionId}.");
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            WaitForDebugger();

            Random random = new Random();

            bool processStarted = false;
            
            while (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogInformation("Worker running at: {time}", DateTimeOffset.Now);

                if (!processStarted)
                {
                    try
                    {
                        SessionInfo sessionInfo = GetActiveSessionInfo();
                        if (string.IsNullOrEmpty(sessionInfo.UserName) || sessionInfo.SessionId < 0)
                        {
                            _logger.LogWarning("No active user session found at: {time}", DateTimeOffset.Now);
                            Thread.Sleep(10000);
                            return;
                        }
                        else
                            _logger.LogDebug("Active user: {userName} at: {time}", sessionInfo.UserName,
                                DateTimeOffset.Now);

                        LaunchProcessWithSessionPrivileges(sessionInfo, @"C:\Windows\System32\cmd.exe");

                        processStarted = true;
                    }
                    catch (Exception e)
                    {
                        _logger.LogError($"Process was not started: {e.Message}", e);
                    }
                }

                //if (GetLastInputTime() >= _settings.MouseInactivityThresholdInSeconds)
                //{
                //    IntPtr hWnd = FindWindow(_settings.ApplicationName, null);

                //    if (hWnd != IntPtr.Zero)
                //    {
                //        SetForegroundWindow(hWnd);
                //        _logger.LogInformation("Set focus to {appName} at: {time}", _settings.ApplicationName, DateTimeOffset.Now);

                //        if (GetWindowRect(hWnd, out RECT rect))
                //        {
                //            int x = random.Next(rect.Left, rect.Right);
                //            int y = random.Next(rect.Top, rect.Bottom);
                //            SetCursorPos(x, y);
                //            _logger.LogInformation("Moved mouse cursor to ({x}, {y}) at: {time}", x, y, DateTimeOffset.Now);
                //        }
                //    }
                //    else
                //    {
                //        _logger.LogWarning("{appName} window not found at: {time}", _settings.ApplicationName, DateTimeOffset.Now);
                //    }
                //}
                //else
                //{
                //    _logger.LogInformation("Mouse has been moved recently. Skipping actions at: {time}", DateTimeOffset.Now);
                //}

                //if (impersonated)
                //{
                //    RevertToSelf();
                //    CloseHandle(userToken);
                //}

                await Task.Delay(_settings.DelayInSeconds * 1000, stoppingToken);
            }
        }

        private bool StartProcessAsUser(uint processId, string commandline)
        {
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.Length = Marshal.SizeOf(sa);

            using (SafeProcessHandle hProcess = OpenProcess(MAXIMUM_ALLOWED, false, processId))
            using (SafeTokenHandle hPToken = OpenProcessTokenHandle(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY |
                                                                              TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                                                                              TOKEN_ADJUST_SESSIONID | TOKEN_READ | TOKEN_WRITE))
            using (SafeTokenHandle hUserTokenDup = DuplicateUserToken(hPToken, sa))
            {
                if (hProcess.IsInvalid || hPToken.IsInvalid || hUserTokenDup.IsInvalid)
                {
                    _logger.LogError("Failed to acquire necessary handles.");
                    return false;
                }

                uint dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;

                IntPtr pEnv = IntPtr.Zero;
                try
                {
                    if (CreateEnvironmentBlock(ref pEnv, hUserTokenDup, true))
                    {
                        dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
                    }

                    STARTUPINFO si = new STARTUPINFO();
                    si.cb = Marshal.SizeOf(si);
                    si.lpDesktop = "winsta0\\default";

                    PROCESS_INFORMATION pi;
                    bool bResult = CreateProcessAsUser(hUserTokenDup, // client's access token
                        null, // file to execute
                        commandline, // command line
                         ref sa, // pointer to process SECURITY_ATTRIBUTES
                        ref sa, // pointer to thread SECURITY_ATTRIBUTES
                        false, // handles are not inheritable
                        dwCreationFlags, // creation flags
                        pEnv, // pointer to new environment block 
                        null, // name of current directory 
                        ref si, // pointer to STARTUPINFO structure
                        out pi // receives information about new process
                    );

                    return bResult;
                }
                finally
                {
                    if (pEnv != IntPtr.Zero) DestroyEnvironmentBlock(pEnv);
                }
            }
        }

        private SafeTokenHandle DuplicateUserToken(SafeTokenHandle handleProcessToken, SECURITY_ATTRIBUTES sa)
        {
            if (!DuplicateTokenEx(handleProcessToken, MAXIMUM_ALLOWED, ref sa,
                    SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                    TOKEN_TYPE.TokenPrimary, out SafeTokenHandle duplicateUserToken))
            {
                throw new InvalidOperationException($"DuplicateTokenEx failed. Error: {Marshal.GetLastWin32Error()}");
            }

            return duplicateUserToken;
        }

        private int GetLastInputTime()
        {
            LASTINPUTINFO lastInputInfo = new LASTINPUTINFO();
            lastInputInfo.cbSize = (uint)Marshal.SizeOf(lastInputInfo);
            if (GetLastInputInfo(ref lastInputInfo))
            {
                return (Environment.TickCount - (int)lastInputInfo.dwTime) / 1000;
            }
            return 0;
        }

        private bool IsServiceInteractive()
        {
            return Process.GetCurrentProcess().SessionId == WTSGetActiveConsoleSessionId();
        }

        private uint GetFirstProcessIdFromUserSession(SessionInfo sessionInfo)
        {
            if (sessionInfo == null || sessionInfo.SessionId == -1) return 0;

            IntPtr handleToSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (handleToSnapshot == IntPtr.Zero) return 0;

            try
            {
                PROCESSENTRY32 processEntry = new PROCESSENTRY32();
                processEntry.dwSize = (uint)Marshal.SizeOf(processEntry);

                if (!Process32First(handleToSnapshot, ref processEntry)) return 0;
                do
                {
                    uint sessionId = 0;
                    if (!ProcessIdToSessionId((uint)processEntry.th32ProcessID, ref sessionId)) continue; 
                    if (sessionId != sessionInfo.SessionId) continue;

                    string userName = GetProcessUsername((int)processEntry.th32ProcessID);
                    if (userName == null || !userName.EndsWith(sessionInfo.UserName)) continue;

                    _logger.LogDebug($"Process found: {processEntry.szExeFile}, ID: {processEntry.th32ProcessID}, Session ID: {sessionId}, User: {userName}");
                    return processEntry.th32ProcessID;
                }
                while (Process32Next(handleToSnapshot, ref processEntry));

                return 0;
            }
            finally
            {
                CloseHandle(handleToSnapshot);
            }
        }

        private string GetProcessUsername(int processId)
        {
            try
            {
                using (Process process = Process.GetProcessById(processId))
                using (SafeProcessHandle processHandle = new SafeProcessHandle(process.Handle, false))
                using (SafeTokenHandle tokenHandle = OpenProcessTokenHandle(processHandle, TOKEN_QUERY))
                {
                    uint tokenInformationLength = 0;
                    GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, tokenInformationLength, out tokenInformationLength);

                    IntPtr tokenInformation = Marshal.AllocHGlobal((int)tokenInformationLength);
                    try
                    {
                        if (tokenInformation != IntPtr.Zero && GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser, tokenInformation, tokenInformationLength, out tokenInformationLength))
                        {
                            if (tokenInformation != IntPtr.Zero)
                            {
                                TOKEN_USER tokenUser =
                                    (TOKEN_USER)Marshal.PtrToStructure(tokenInformation, typeof(TOKEN_USER));
                                IntPtr userSid = tokenUser.User.Sid;
                                if (userSid != IntPtr.Zero)
                                {
                                    string accountName = new SecurityIdentifier(userSid)
                                        .Translate(typeof(NTAccount))
                                        .ToString();
                                    return accountName;
                                }
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(tokenInformation);
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"Access denied for process {processId}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to get user name for process {processId}: {ex.Message}");
            }

            return null;
        }

        private SafeTokenHandle OpenProcessTokenHandle(SafeProcessHandle processHandle, UInt32 desiredAccess)
        {
            if (!OpenProcessToken(processHandle, TOKEN_QUERY, out SafeTokenHandle tokenHandle))
            {
                throw new InvalidOperationException($"OpenProcessToken failed. Error: {Marshal.GetLastWin32Error()}");
            }
            return tokenHandle;
        }

        private SessionInfo GetActiveSessionInfo()
        {
            SessionInfo result = new SessionInfo
            {
                DesktopName = null,
                SessionId = -1,
                UserName = null
            };
            IntPtr ppSessionInfo = IntPtr.Zero;
            int count = 0;
            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref ppSessionInfo, ref count) != 0)
            {
                IntPtr current = ppSessionInfo;
                for (int i = 0; i < count; i++)
                {
                    WTS_SESSION_INFO sessionInfo = Marshal.PtrToStructure<WTS_SESSION_INFO>(current);
                    current += Marshal.SizeOf<WTS_SESSION_INFO>();

                    if (sessionInfo.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                    {
                        IntPtr buffer;
                        uint strLen;
                        if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessionInfo.SessionId, WTS_INFO_CLASS.WTSUserName, out buffer, out strLen) && strLen > 1)
                        {
                            string userName = Marshal.PtrToStringAnsi(buffer);
                            WTSFreeMemory(buffer);

                            if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessionInfo.SessionId, WTS_INFO_CLASS.WTSWinStationName, out buffer, out strLen) && strLen > 1)
                            {
                                result.DesktopName = Marshal.PtrToStringAnsi(buffer);
                                WTSFreeMemory(buffer);
                            }
                            else
                            {
                                int errorCode = Marshal.GetLastWin32Error();
                                _logger.LogError("WTSQuerySessionInformation failed for WTSWinStationName. SessionId: {sessionId}, ErrorCode: {errorCode}", sessionInfo.SessionId, errorCode);
                            }

                            result.SessionId = sessionInfo.SessionId;
                            result.UserName = userName;
                            return result;
                        }
                    }
                    else
                    {
                        int errorCode = Marshal.GetLastWin32Error();
                        _logger.LogError("WTSQuerySessionInformation failed for WTSUserName. SessionId: {sessionId}, ErrorCode: {errorCode}", sessionInfo.SessionId, errorCode);
                    }
                }
                WTSFreeMemory(ppSessionInfo);
            }

            return result;
        }

        private void WaitForDebugger()
        {
            if (!Debugger.IsAttached)
            {
                _logger.LogInformation("Waiting for debugger to attach...");
                while (!Debugger.IsAttached)
                {
                    Thread.Sleep(100);
                }
                _logger.LogInformation("Debugger attached. Continuing execution...");
            }
        }

        #region SafeHandles

        public class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeTokenHandle() : base(true) { }

            protected override bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
        }

        public class SafeProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeProcessHandle()
                : base(true)
            {
            }

            public SafeProcessHandle(IntPtr existingHandle, bool ownsHandle)
                : base(ownsHandle)
            {
                SetHandle(existingHandle);
            }

            protected override bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
        }

        #endregion

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetThreadDesktop(IntPtr hDesktop);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseDesktop(IntPtr hDesktop);

        private const uint DESKTOP_READOBJECTS = 0x0001;
        private const uint DESKTOP_CREATEWINDOW = 0x0002;
        private const uint DESKTOP_CREATEMENU = 0x0004;
        private const uint DESKTOP_HOOKCONTROL = 0x0008;
        private const uint DESKTOP_JOURNALRECORD = 0x0010;
        private const uint DESKTOP_JOURNALPLAYBACK = 0x0020;
        private const uint DESKTOP_ENUMERATE = 0x0040;
        private const uint DESKTOP_WRITEOBJECTS = 0x0080;
        private const uint DESKTOP_SWITCHDESKTOP = 0x0100;

        private const uint MAXIMUM_ALLOWED = 0x2000000;

        #region rights constants

        public const int READ_CONTROL = 0x00020000;

        public const int STANDARD_RIGHTS_REQUIRED = 0x000F0000;

        public const int STANDARD_RIGHTS_READ = READ_CONTROL;
        public const int STANDARD_RIGHTS_WRITE = READ_CONTROL;
        public const int STANDARD_RIGHTS_EXECUTE = READ_CONTROL;

        public const int STANDARD_RIGHTS_ALL = 0x001F0000;

        public const int SPECIFIC_RIGHTS_ALL = 0x0000FFFF;

        public const int TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const int TOKEN_DUPLICATE = 0x0002;
        public const int TOKEN_IMPERSONATE = 0x0004;
        public const int TOKEN_QUERY = 0x0008;
        public const int TOKEN_QUERY_SOURCE = 0x0010;
        public const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const int TOKEN_ADJUST_GROUPS = 0x0040;
        public const int TOKEN_ADJUST_DEFAULT = 0x0080;
        public const int TOKEN_ADJUST_SESSIONID = 0x0100;

        public const int TOKEN_ALL_ACCESS_P = (STANDARD_RIGHTS_REQUIRED |
                                               TOKEN_ASSIGN_PRIMARY |
                                               TOKEN_DUPLICATE |
                                               TOKEN_IMPERSONATE |
                                               TOKEN_QUERY |
                                               TOKEN_QUERY_SOURCE |
                                               TOKEN_ADJUST_PRIVILEGES |
                                               TOKEN_ADJUST_GROUPS |
                                               TOKEN_ADJUST_DEFAULT);

        public const int TOKEN_ALL_ACCESS = TOKEN_ALL_ACCESS_P | TOKEN_ADJUST_SESSIONID;

        public const int TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY;

        public const int TOKEN_WRITE = STANDARD_RIGHTS_WRITE |
                                       TOKEN_ADJUST_PRIVILEGES |
                                       TOKEN_ADJUST_GROUPS |
                                       TOKEN_ADJUST_DEFAULT;

        public const int TOKEN_EXECUTE = STANDARD_RIGHTS_EXECUTE;

        #endregion

        public const string SE_DEBUG_NAME = "SeDebugPrivilege";
        public const string SE_RESTORE_NAME = "SeRestorePrivilege";
        public const string SE_BACKUP_NAME = "SeBackupPrivilege";

        public const int CREATE_NEW_PROCESS_GROUP = 0x00000200;
        public const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;

        public const int IDLE_PRIORITY_CLASS = 0x40;
        public const int NORMAL_PRIORITY_CLASS = 0x20;
        public const int HIGH_PRIORITY_CLASS = 0x80;
        public const int REALTIME_PRIORITY_CLASS = 0x100;

        public const int CREATE_NEW_CONSOLE = 0x00000010;

        private const uint TH32CS_SNAPPROCESS = 0x00000002;

        private static int INVALID_HANDLE_VALUE = -1;

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, SafeTokenHandle hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetCursorPos(int x, int y);

        [DllImport("wtsapi32.dll")]
        private static extern int WTSEnumerateSessions(IntPtr hServer, int reserved, int version, ref IntPtr ppSessionInfo, ref int pCount);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("wtsapi32.dll")]
        private static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr ppBuffer, out uint pBytesReturned);

        [DllImport("wtsapi32.dll")]
        private static extern bool WTSQueryUserToken(uint sessionId, out SafeTokenHandle phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ImpersonateLoggedOnUser(SafeTokenHandle hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(SafeProcessHandle ProcessHandle, UInt32 DesiredAccess, out SafeTokenHandle TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(SafeTokenHandle TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LookupPrivilegeValue(IntPtr lpSystemName, string lpname, [MarshalAs(UnmanagedType.Struct)] ref LUID lpLuid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private extern static bool DuplicateTokenEx(SafeTokenHandle hExistingToken, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out SafeTokenHandle phNewToken);

        //[DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        //private static extern bool CreateProcessAsUser(SafeTokenHandle hToken, string lpApplicationName, string lpCommandLine,
        //    ref SECURITY_ATTRIBUTES lpProcessAttributes,
        //    ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
        //    string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessAsUser(SafeTokenHandle hToken, string lpApplicationName, string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,
            uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        private static extern bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        private static extern bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot([In] UInt32 dwFlags, [In] UInt32 th32ProcessID);


        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ProcessIdToSessionId(uint dwProcessId, ref uint pSessionId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeProcessHandle OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RevertToSelf();

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        private enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_USER
        {
            public _SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct _SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }
        
        private enum WTS_INFO_CLASS
        {
            WTSWinStationName = 0,
            WTSUserName = 5,
        }

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public int SessionId;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pWinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LASTINPUTINFO
        {
            public uint cbSize;
            public uint dwTime;
        }

        #region Nested type: LUID

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID
        {
            public int LowPart;
            public int HighPart;
        }

        #endregion

        #region Nested type: LUID_AND_ATRIBUTES

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID_AND_ATRIBUTES
        {
            public LUID Luid;
            public int Attributes;
        }

        #endregion

        #region Nested type: SECURITY_ATTRIBUTES

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        #endregion

        #region Nested type: SECURITY_IMPERSONATION_LEVEL

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        #endregion

        #region Nested type: TOKEN_TYPE

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        #endregion

        #region Nested type: PROCESS_INFORMATION

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        #endregion

        #region Nested type: PROCESSENTRY32

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public readonly uint cntUsage;
            public readonly uint th32ProcessID;
            public readonly IntPtr th32DefaultHeapID;
            public readonly uint th32ModuleID;
            public readonly uint cntThreads;
            public readonly uint th32ParentProcessID;
            public readonly int pcPriClassBase;
            public readonly uint dwFlags;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public readonly string szExeFile;
        }

        #endregion

        #region Nested type: STARTUPINFO

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        #endregion
    }
}