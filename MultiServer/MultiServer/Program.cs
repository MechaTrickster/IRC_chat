using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MultiServer
{
    class Program
    {
        private static byte[] _buffer = new byte[1024];
        private static List<Socket> _clientSockets = new List<Socket>();
        private static Socket _serverSocket = new Socket
            (AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        public static RSAParameters publicParam;

        static X509Certificate2 certp;

        private static List<Utente> _utenti = new List<Utente>();


        static void Main(string[] args)
        {
            certp = new X509Certificate2("public.cer");

            var publicKey = certp.GetRSAPublicKey();

            publicParam = publicKey.ExportParameters(false);

            Console.WriteLine(certp);

            Console.Title = "SERVER";
            SetupServer();
            Console.ReadLine();
        }

        private static void SetupServer()
        {
            Console.WriteLine("Avvio server...");
            _serverSocket.Bind(new IPEndPoint(IPAddress.Any, 100));
            _serverSocket.Listen(1);

            _serverSocket.BeginAccept(new AsyncCallback(AcceptCallback), null);
        }

        private static void AcceptCallback(IAsyncResult AR)
        {
            Socket socket = _serverSocket.EndAccept(AR);
            _clientSockets.Add(socket);
            Utente utente = new Utente();
            utente.socket = socket;


            _utenti.Add(utente);

            Console.WriteLine("Client connesso");
            socket.BeginReceive(_buffer, 0, _buffer.Length, SocketFlags.None, 
                                new AsyncCallback(ReceiveCallback), socket);
            _serverSocket.BeginAccept(new AsyncCallback(AcceptCallback), null);
        }

        private static void ReceiveCallback(IAsyncResult AR)
        {
            Socket socket = (Socket)AR.AsyncState;

            Socket tempSocket = socket;

            int received = socket.EndReceive(AR);
            byte[] dataBuf = new byte[received];
            Array.Copy(_buffer, dataBuf, received);
            string text = Encoding.ASCII.GetString(dataBuf);

            Console.WriteLine(text);

            string[] splits = text.Split("*/*");


            if (VerifySignature(splits[1], splits[2], publicParam))
            {
                Console.WriteLine("firma verificata");

                if (splits[0].Contains("/room"))
                {
                    foreach (Utente u in _utenti)
                    {
                        if (u.socket == tempSocket)
                        {
                            string stanza = splits[0].Remove(0, 5);
                            u.room = stanza;
                            Console.WriteLine(u.room);
                        }
                    }
                }
                else
                {
                    byte[] data = Encoding.ASCII.GetBytes(splits[0]);

                    string userRoom = "";

                    foreach (Utente u in _utenti)
                    {
                        if (u.socket == tempSocket)
                        {
                            userRoom = u.room;
                        }
                    }

                    foreach (Utente u in _utenti)
                    {
                        if (u.socket != tempSocket)
                            if (u.room == userRoom)
                                u.socket.BeginSend(data, 0, data.Length, SocketFlags.None,
                    new AsyncCallback(SendCalback), u.socket);
                    }
                }
            }
            else
            {
                Console.WriteLine("firma NON verificata");

            }

            string response = string.Empty;

            socket.BeginReceive(_buffer, 0, _buffer.Length, SocketFlags.None,
                                new AsyncCallback(ReceiveCallback), socket);
        }

        private static void SendCalback(IAsyncResult AR)
        {
            Socket socket = (Socket)AR.AsyncState;
            socket.EndSend(AR);
        }

        public static bool VerifySignature(String value, String signature, RSAParameters publicParam)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            rsa.ImportParameters(publicParam);

            RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(rsa);

            RSADeformatter.SetHashAlgorithm("SHA256");

            SHA256Managed SHhash = new SHA256Managed();

            if (RSADeformatter.VerifySignature(SHhash.ComputeHash(new UnicodeEncoding().GetBytes(value)), System.Convert.FromBase64String(signature)))
            {
                //la firma è valida
                return true;
            }
            else
            {
                //la firma non è valida
                return false;
            }
        }
    }
}
