using System;
using System.IO;

namespace Heuristic_analysis
{
    class Program
    {
        private static string PathToFolder = @"D:\Проверка";
        private static double rez = 0;
        private static string[] Signat_Original = new string[4] { "MZ", "PE", "ёPNG", "ID3" };
        private static byte[] JMP = new byte[] { 116, 117, 119, 235, 90 };
        private static byte[,] DelFile = new byte[,] { { 205, 65 } , { 205, 64 } };
        private static byte[][] Signatures = {
                         new byte[2] { 77, 90 },
                         new byte[4] { 137, 80, 78, 71},
                         new byte[3] { 73,68, 51},
                         new byte[2] { 80, 69 },
        };
        private static double[] score = { 0.4, 0.3, 0.2, 0.1, 0.3, 0.4, 0.3, 0.6, 0.4 };
        private static double[] fin_score = { 0.3, 0.1, 0.6 };
        static void Main(string[] args)
        {
            string[] allfiles = Directory.GetFiles(PathToFolder);
            foreach (string filename in allfiles)
            {
                rez = 0;
                Console.WriteLine();
                byte[] data = File.ReadAllBytes(filename);
                rez += SignatureAnaliz(data) * fin_score[0];
                rez += NameFile(Path.GetFileName(filename)) * fin_score[1];
                rez += InFile(data) * fin_score[2];
                if (rez < 0.2) { Console.Write("{0,50}\t безопасен\t {1:f2}",filename, rez); }
                if (rez>=0.2 && rez<0.7) { Console.Write("{0,50}\t подозрительный\t {1:f2}", filename, rez); }
                if (rez >= 0.7) { Console.Write("{0,50}\t с вирусом\t {1:f2}", filename, rez); }
            }
        }
        private static double SignatureAnaliz(byte[] s) //Проверка на сигнатуры "MZ" (0.4), "PE" (0.3), ".PNG" (0.2), "ID3" (0.1)  ---- Итоговый коэф - 0.35
        {
            bool mmm = false;
            double final_rez = 0;
            for (int i=0; i<3; i++)
            {
                for (int j =0; j<Signatures[i].Length; j++)
                {
                    if (s[j] != Signatures[i][j])
                    {
                        mmm = true;
                    }
                }
                if (!mmm) { final_rez += score[i]; }
                mmm = false;
            }
            if (s.Length > 400)
            {
                for (int j = 0; j < Signatures[3].Length; j++)
                {
                    if (s[j + 296] != Signatures[3][j])
                    {
                        mmm = true;
                    }
                }
                if (!mmm) { final_rez += score[3]; }
            }
            return final_rez;
        }

        private static double NameFile(string s) //Проверка на имя файла, проверка на 5 пробелов и больше (0.3), нет расширения или их много (0.4), имя файла 
        {                                 //состоит из одних пробелов (0.3) и итоговой кожф - 0.15
            double final_rez = 0;
            int mmm = 0, brrr = 0;
            for (int i=0;i<s.Length;i++)
            {
                if (s[i] == ' ') { mmm++; }
                if (s[i] == '.') { brrr++; }
            }
            if (mmm >= 5 )
            {
                final_rez += score[4];
            } 
            if (brrr != 1)
            {
                final_rez += score[5];
            }
            if (mmm == s.Length)
            {
                final_rez += score[6];
            }
            return final_rez;
        }
        private static double InFile(byte[] s) //Проверка на прыжки (0.6) и удаление файлов (0.4)  ---- Итоговый коэф - 0.5
        {
            int mmm = 0;
            double final_rez = 0;
            foreach (byte k in s)
            {
                for (int i = 0; i < 5; i++)
                {
                    if (k == JMP[i]) { mmm += 1; }
                }
            }
            if (mmm != 0) {
                if (s.Length / mmm < 50)
                {
                    final_rez += score[7];
                }
            }
            mmm = 0;
            for (int i = 0; i < s.Length-1; i++)
            {
                if ((s[i]==DelFile[0,0] || s[i] == DelFile[1, 0]) && (s[i+1] == DelFile[0, 1] || s[i+1] == DelFile[1, 1]))
                {
                    mmm += 1;
                }
            }
            if (mmm != 0)
            {
                if (s.Length / mmm < 100) { final_rez += score[8]; }
            }
            return final_rez;
        }
    }
}
