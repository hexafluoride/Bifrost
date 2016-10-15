using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost
{
    public class HandshakeResult
    {
        public HandshakeResultType Type { get; set; }
        public string Message { get; set; }
        public double TimeDrift { get; set; }

        internal HandshakeResult(HandshakeResultType type, string message, params object[] format)
        {
            Type = type;
            Message = string.Format(message, format);
        }

        public static HandshakeResult CreateFromError(Logger logger, HandshakeResultType type, string message, params object[] format)
        {
            message = string.Format(message, format);
            logger.Error(message);

            return new HandshakeResult(type, message, format);
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
