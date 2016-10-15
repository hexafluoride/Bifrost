using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost
{
    /// <summary>
    /// Describes the result of a PerformHandshake() call.
    /// </summary>
    public class HandshakeResult
    {
        /// <summary>
        /// Contains the result type.
        /// </summary>
        public HandshakeResultType Type { get; set; }
        /// <summary>
        /// A human-readable message detailing the handshake attempt.
        /// </summary>
        public string Message { get; set; }
        /// <summary>
        /// If the handshake was successful, returns the time drift in seconds between the two peers.
        /// </summary>
        public double TimeDrift { get; set; }

        /// <summary>
        /// Creates a HandshakeResult object.
        /// </summary>
        /// <param name="type">The result type.</param>
        /// <param name="message">A human-readable message.</param>
        /// <param name="format">Format objects for the human-readable message.</param>
        internal HandshakeResult(HandshakeResultType type, string message, params object[] format)
        {
            Type = type;
            Message = string.Format(message, format);
        }
    }

    public enum HandshakeResultType
    {
        Other = 0x00,
        Successful,
        ConnectionClosed,
        Timeout,
        ReplayAttack,
        UntrustedStaticPublicKey,
        UntrustedTimestamp,
        UntrustedEphemeralPublicKey,
        UnexpectedMessage
    }
}
