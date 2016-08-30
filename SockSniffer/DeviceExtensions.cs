using System.Text;
using PcapDotNet.Core;

namespace SockSniffer
{
    public static class DeviceExtensions
    {
        // Returns a human readable string containing information about a given device
        public static string DeviceInformation(this IPacketDevice ipd)
        {
            var sb = new StringBuilder();

            sb.AppendLine(ipd.Name);
            if (ipd.Description != null)
                sb.Append("\tDescription: ").AppendLine(ipd.Description);
            sb.Append("\tLoopback: ").AppendLine((ipd.Attributes & DeviceAttributes.Loopback) == DeviceAttributes.Loopback ? "yes" : "no");
            foreach (DeviceAddress address in ipd.Addresses)
            {
                sb.Append($"\tAddress Family: ").AppendLine(address.Address.Family.ToString());
                if (address.Address != null)
                    sb.Append("\tAddress: ").AppendLine(address.Address.ToString());
                if (address.Netmask != null)
                    sb.Append("\tNetmask: ").AppendLine(address.Netmask.ToString());
                if (address.Broadcast != null)
                    sb.Append("\tBroadcast Address: ").AppendLine(address.Broadcast.ToString());
                if (address.Destination != null)
                    sb.Append("\tDestination: ").AppendLine(address.Destination.ToString());
            }
            return sb.ToString();
        }
    }
}