using static System.Console;
using System.Linq;
using WebSocketSharp;
using WebSocketSharp.Server;

namespace TestServer
{
    static class StringExtensions
    {
        public static string Reverse(this string s)
        {
            return new string(s.ToCharArray().Reverse().ToArray());
        }
    }

    public class Reverser : WebSocketBehavior
    {
        protected override void OnMessage(MessageEventArgs e)
        {
            WriteLine($"Message received: {e.Data}");
            Send(e.Data.Reverse());            
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var reverser = new WebSocketServer(5656);
            reverser.AddWebSocketService<Reverser>("/reverse");
            reverser.Start();
            ReadKey(true);
            reverser.Stop();
        }
    }
}
