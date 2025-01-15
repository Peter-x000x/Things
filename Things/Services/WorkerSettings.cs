using System;

namespace Things.Services
{
    public class WorkerSettings
    {
        public string ApplicationName { get; set; }

        public int DelayInSeconds { get; set; }

        public int MouseInactivityThresholdInSeconds { get; set; }

        public string PipeName { get; set; }
    }
}
