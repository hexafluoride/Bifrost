using System;
using System.Threading;
using System.Reflection;
using System.Diagnostics;

using NLog;

namespace Bifrost
{
    public class Utilities
    {
        private static Logger Log = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// Starts a new thread with the given delegate. Useful for not getting bottlenecked by ThreadPool.
        /// </summary>
        /// <param name="action">The delegate to execute.</param>
        /// <returns>The created thread.</returns>
        public static Thread StartThread(Action action)
        {
            Thread thr = new Thread(() => action());
            thr.Start();
            return thr;
        }

        /// <summary>
        /// Logs the Bifrost version as patched by AppVeyor.
        /// </summary>
        public static void LogVersion()
        {
            string version = FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).ProductVersion;
            Log.Info("Bifrost version {0}", version);
        }
    }
}