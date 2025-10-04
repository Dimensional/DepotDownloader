// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;

namespace DepotDownloader
{
    public static class DebugLog
    {
        public static bool Enabled { get; set; } = false;

        private static readonly List<Action<string, string>> listeners = new();

        public static void AddListener(Action<string, string> listener)
        {
            listeners.Add(listener);
        }

        public static void WriteLine(string category, string format, params object[] args)
        {
            if (!Enabled)
                return;

            var message = string.Format(format, args);
            foreach (var listener in listeners)
            {
                listener(category, message);
            }
        }
    }
}
