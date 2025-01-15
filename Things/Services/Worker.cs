using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Things.Services
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly WorkerSettings _settings;

        public Worker(ILogger<Worker> logger, IOptions<WorkerSettings> settings)
        {
            _logger = logger;
            _settings = settings.Value;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            Random random = new Random();

            while (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogInformation("Worker running at: {time}", DateTimeOffset.Now);

                if (GetLastInputTime() >= _settings.MouseInactivityThresholdInSeconds)
                {
                    string userName = GetActiveUserName();
                    if (string.IsNullOrEmpty(userName))
                    {
                        _logger.LogWarning("No active user session found at: {time}", DateTimeOffset.Now);
                    }
                    else
                    {
                        _logger.LogInformation("Active user: {userName} at: {time}", userName, DateTimeOffset.Now);

                        IntPtr hWnd = IntPtr.Zero;
                        IntPtr userToken = IntPtr.Zero;
                        bool impersonated = !userName.Equals(Environment.UserName, StringComparison.OrdinalIgnoreCase) && ImpersonateActiveUserSession(out userToken);

                        hWnd = FindWindow(_settings.ApplicationName, null);

                        if (hWnd != IntPtr.Zero)
                        {
                            SetForegroundWindow(hWnd);
                            _logger.LogInformation("Set focus to {appName} at: {time}", _settings.ApplicationName, DateTimeOffset.Now);

                            if (GetWindowRect(hWnd, out RECT rect))
                            {
                                int x = random.Next(rect.Left, rect.Right);
                                int y = random.Next(rect.Top, rect.Bottom);
                                SetCursorPos(x, y);
                                _logger.LogInformation("Moved mouse cursor to ({x}, {y}) at: {time}", x, y, DateTimeOffset.Now);
                            }
                        }
                        else
                        {
                            _logger.LogWarning("{appName} window not found at: {time}", _settings.ApplicationName, DateTimeOffset.Now);
                        }

                        if (impersonated)
                        {
                            RevertToSelf();
                            CloseHandle(userToken);
                        }
                    }
                }
                else
                {
                    _logger.LogInformation("Mouse has been moved recently. Skipping actions at: {time}", DateTimeOffset.Now);
                }

                await Task.Delay(_settings.DelayInSeconds * 1000, stoppingToken);
            }
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

        private string GetActiveUserName()
        {
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
                            return userName;
                        }
                    }
                }
                WTSFreeMemory(ppSessionInfo);
            }
            return null;
        }

        private bool ImpersonateActiveUserSession(out IntPtr userToken)
        {
            userToken = IntPtr.Zero;
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
                        if (WTSQueryUserToken((uint)sessionInfo.SessionId, out userToken))
                        {
                            if (ImpersonateLoggedOnUser(userToken))
                            {
                                WTSFreeMemory(ppSessionInfo);
                                return true;
                            }
                            CloseHandle(userToken);
                        }
                    }
                }
                WTSFreeMemory(ppSessionInfo);
            }
            return false;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetCursorPos(int X, int Y);

        [DllImport("wtsapi32.dll")]
        private static extern int WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, ref IntPtr ppSessionInfo, ref int pCount);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("wtsapi32.dll")]
        private static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr ppBuffer, out uint pBytesReturned);

        [DllImport("wtsapi32.dll")]
        private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RevertToSelf();

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        private enum WTS_INFO_CLASS
        {
            WTSUserName = 5
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
    }
}