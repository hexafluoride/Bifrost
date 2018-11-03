using System;

namespace Bifrost
{
    /// <summary>
    /// Describes a common interface that all tunnels should implement.
    /// </summary>
    public interface ITunnel
    {
        long RawBytesSent { get; set; }
        long DataBytesSent { get; set; }
        long RawBytesReceived { get; set; }
        long DataBytesReceived { get; set; }

        ulong PacketsDropped { get; }
        ulong PacketsReceived { get; }

        bool Closed { get; set; }
        void Send(byte[] data);
        byte[] Receive();

        void Close();
    }
}

