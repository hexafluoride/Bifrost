using System;
using System.Threading;

namespace Bifrost
{
    public class Utilities
    {
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
    }
}

