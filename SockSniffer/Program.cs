using static System.Console;
using System.Collections.Generic;
using PcapDotNet.Core;

namespace SockSniffer
{
    class Program
    {
        public static void Main(string[] args)
        {
            var producer = new LivePacketProducer(SelectListenDevice());
            //producer.AddConsumer(new TrafficLogger());
            producer.AddConsumer(new WebSocketDetector());
            producer.UpdateForever();
        }

        // Enumerates all available devices to the console and prompts the user to choose one
        public static LivePacketDevice SelectListenDevice()
        {
            IList<LivePacketDevice> devices = LivePacketDevice.AllLocalMachine;

            if (devices.Count == 0)
            {
                WriteLine("No network interfaces found. Make sure WinPCap is installed.");
                return null;
            }

            // List the devices
            foreach (LivePacketDevice device in devices)
                WriteLine(device.DeviceInformation());

            // Have the user select a device
            int deviceNo = 0;
            while (deviceNo == 0)
            {
                WriteLine($"Choose an interface (1-{devices.Count}): ");
                if (!int.TryParse(ReadLine(), out deviceNo) || deviceNo < 1 || deviceNo > devices.Count)
                    deviceNo = 0;
            }
            return devices[deviceNo - 1];
        }
    }
}
