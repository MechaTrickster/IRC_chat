using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace MultiClient
{
    class Program
    {
        private static Socket _clientSocket = new Socket(AddressFamily.InterNetwork, 
                                                            SocketType.Stream, ProtocolType.Tcp);

        public static RSACryptoServiceProvider rsa;
        public static RSAParameters privateParam;
        public static RSAParameters publicParam;

        static bool once = true;

        static string s = "/room";

        static byte[] buffer;

        public static void ThreadProc()
        {
            Console.Write("Inserisci il tuo nome: ");

            string nickName = Console.ReadLine();

            Console.WriteLine("Benvenuto " + nickName);

            //legge la stringa da tastiera e la converte in byte

            string dataLength;

            //byte[] signature = Encoding.ASCII.GetBytes(signMessage(textLength.ToString(), privateParam));

            string hash;
            string mex;
            

            byte[] hashByte;
            byte[] lengthByte;
            byte[] sendPacket;

            while (true)
            {
                if (once)
                {
                    Console.WriteLine("Scegli la stanza: ");
                    mex = Console.ReadLine();
                    buffer = Encoding.ASCII.GetBytes(s + mex);
                    once = false;
                }
                else
                {
                    mex = Console.ReadLine();
                    buffer = Encoding.ASCII.GetBytes(nickName + ": " + mex);
                }
                    
                dataLength = buffer.Length.ToString();

                hash = SignMessage(dataLength, privateParam);

                hashByte = Encoding.ASCII.GetBytes(hash);

                lengthByte = Encoding.ASCII.GetBytes("*/*" + dataLength + "*/*");

                sendPacket = new byte[buffer.Length + lengthByte.Length + hashByte.Length];

                System.Buffer.BlockCopy(buffer, 0, sendPacket, 0, buffer.Length);
                System.Buffer.BlockCopy(lengthByte, 0, sendPacket, buffer.Length, lengthByte.Length);
                System.Buffer.BlockCopy(hashByte, 0, sendPacket, buffer.Length + lengthByte.Length, hashByte.Length);

                _clientSocket.Send(sendPacket);
            }
        }

        static void Main(string[] args)
        {
            X509KeyStorageFlags flags = X509KeyStorageFlags.Exportable;
            X509Certificate2 cert = new X509Certificate2("cert_key.p12", "finalfantasy", flags);

            //esporta i parametri della chiave privata
            //privateParam = rsa.ExportParameters(true);

            var privateKey = cert.GetRSAPrivateKey();
            //var publicKey = certp.GetRSAPublicKey();

            privateParam = privateKey.ExportParameters(true);
            //publicParam = publicKey.ExportParameters(false);

            /*
            //legge la stringa da tastiera e la converte in byte
            byte[] data = Encoding.ASCII.GetBytes(Console.ReadLine());
            string dataLength = data.Length.ToString();

            //byte[] signature = Encoding.ASCII.GetBytes(signMessage(textLength.ToString(), privateParam));

            string hash = signMessage(dataLength, privateParam);
            byte[] hashByte = Encoding.ASCII.GetBytes(hash);


            byte[] lengthByte = Encoding.ASCII.GetBytes("*//*"+dataLength+"*//*");

            byte[] sendPacket = new byte[data.Length + lengthByte.Length + hashByte.Length];

            System.Buffer.BlockCopy(data, 0, sendPacket, 0, data.Length);
            System.Buffer.BlockCopy(lengthByte, 0, sendPacket, data.Length, lengthByte.Length);
            System.Buffer.BlockCopy(hashByte, 0, sendPacket, data.Length + lengthByte.Length, hashByte.Length);
            */

            //string n = System.Text.Encoding.UTF8.GetString(sendPacket);

            
            //string[] splits = n.Split("*/*");

            //Console.WriteLine(splits[0]);
            //Console.WriteLine(splits[1]);
            //Console.WriteLine(splits[2]);


            /*
                data, dataLenght, hash,              

             */

            //Console.WriteLine(Encoding.ASCII.GetString(signature));


            /*    if (verifySignature(1+textLength.ToString(), hash, publicParam))
                {
                    Console.WriteLine("verificato");
                }
                else
                {
                    Console.WriteLine("NON verificato");
                }   */


            /*
            String prova = signMessage("ciao", privateParam);

            if(verifySignature("ciao", prova, publicParam))
            {
                Console.WriteLine("OK");
            }
            else
            {
                Console.WriteLine("miss");
            }
            */

            //lettura chiave pubblica
            //rsa = (RSACryptoServiceProvider)cert.PrivateKey;

            //Console.WriteLine(privateParam);
            //Console.WriteLine(publicParam.ToString());

            //Console.WriteLine(certp);

            Console.Title = "CLIENT";
            LoopConnect();
            Thread t = new Thread(new ThreadStart(ThreadProc));
            t.Start();
            SendLoop();
            Console.ReadLine();
        }

        private static void SendLoop()
        {
            while (true)
            {
                //Thread.Sleep(500);
                //byte[] buffer = Encoding.ASCII.GetBytes(Console.ReadLine());
                //_clientSocket.Send(buffer);
                byte[] receivedBuf = new byte[1024];
                int rec = _clientSocket.Receive(receivedBuf);
                byte[] data = new byte[rec];
                Array.Copy(receivedBuf, data, rec);
                Console.WriteLine("Scrive " + Encoding.ASCII.GetString(data));                

            }
        }

        private static void LoopConnect()
        {
            int attempts = 0;

            while (!_clientSocket.Connected)
            {
                try
                {
                    attempts++;
                    _clientSocket.Connect(IPAddress.Loopback, 100);
                }
                catch (SocketException)
                {
                    Console.Clear();
                    Console.WriteLine("Tentativi di connessione: " + attempts.ToString());
                }
            }

            //converte il certificato in byte[] per l'invio
            //byte[] certData = certp.Export(X509ContentType.Cert);
            //_clientSocket.Send(certData);

            Console.Clear();

            //converte da byte[] a certificato
            //Console.WriteLine(new X509Certificate2(certData));
            Console.WriteLine("Connesso!");
        }

        public static String SignMessage(String value, RSAParameters privateParam)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            rsa.ImportParameters(privateParam);

            //crea un istanza RSAFormatter
            RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(rsa);

            //setta l'algoritmo di hash col quale effettuare la firma
            RSAFormatter.SetHashAlgorithm("SHA256");

            //crea un istanza dell'algoritmo di hash
            SHA256Managed SHhash = new SHA256Managed();

            //converte la stringa in byte, ne calcola l'hash e lo firma
            byte[] SignedHashValue = RSAFormatter.CreateSignature(SHhash.ComputeHash(new UnicodeEncoding().GetBytes(value)));

            //pone il risultato ottenuto in stringa
            string signature = System.Convert.ToBase64String(SignedHashValue);

            return signature;
        }                
    }
}
