///
/// 暗号文の復号処理サンプル
/// 
/// Copyright (c) 2020 Techno Veins Co.,Ltd.
/// 
/// This software is released under the MIT License.
/// http://opensource.org/licenses/mit-license.php
///

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Decrypt
{
    public partial class FormMain : Form
    {
        /// <summary>
        /// 暗号文の拡張子
        /// </summary>
        private const string CryptographyExtName = ".cpt";

        /// <summary>
        /// 書庫ファイル内のデータが格納されているディレクトリ
        /// </summary>
        private const string CryptographySubDir = "aes";

        /// <summary>
        /// 対称鍵のブロックサイズ
        /// </summary>
        private const int BLOCK_SIZE = 128;
        /// <summary>
        /// 対称鍵のキーサイズ
        /// </summary>
        private const int KEY_SIZE = 128;

        /// <summary>
        /// 対称鍵と初期化ベクタを配列で扱うための番号
        /// </summary>
        private enum AesKeys
        {
            key,
            iv,
        };

        public FormMain()
        {
            InitializeComponent();
        }

        /// <summary>
        /// "復号する" ボタンが押されたときの処理
        /// </summary>
        /// <remarks>
        /// 復号する暗号文のファイルを選択し、同じフォルダに復号した平文のファイルを展開する
        /// </remarks>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void buttonDecrypt_Click(object sender, EventArgs e)
        {
            // OpenFileDialog オブジェクト作成
            OpenFileDialog ofd = new OpenFileDialog();
            // ファイル名の初期値を指定する
            ofd.FileName = "";
            // 選択肢を指定する
            ofd.Filter = "暗号ファイル(*" + CryptographyExtName + ")|*" + CryptographyExtName;
            //タイトルを設定する
            ofd.Title = "復号するファイルを選択してください";
            // ダイアログボックスを閉じる前に現在のディレクトリを復元するようにする
            ofd.RestoreDirectory = true;
            // 存在しないファイル名が指定されたとき警告を表示する
            ofd.CheckFileExists = true;
            // 存在しないパスが指定されたとき警告を表示する
            ofd.CheckPathExists = true;
            // ダイアログを表示する
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                // 復号してファイルに書き込む
                string strOutDir = Path.GetDirectoryName(ofd.FileName);
                string strBaseName = Path.GetFileNameWithoutExtension(ofd.FileName);
                string strExtensionName = ".dat";
                string strFilePath = string.Format(@"{0}{1}{2}{3}", strOutDir, (strOutDir.Length > 0 ? @"\" : ""), strBaseName, strExtensionName);
                using (FileStream fs = new FileStream(strFilePath, FileMode.Create, FileAccess.Write))
                {
                    Decrypt(ofd.FileName, fs);
                }
            }
        }

        /// <summary>
        /// 暗号文ファイルを復号して平文ファイルに書き込む
        /// </summary>
        /// <param name="strInPath">暗号文ファイルパス</param>
        /// <param name="strmOut">平文をセーブする開かれたストリーム</param>
        /// <exception cref="System.IO.InvalidDataException">書庫ファイルに指定したファイルが存在しない場合</exception>
        public void Decrypt(string strInPath, Stream strmOut)
        {
            //CspParametersオブジェクトの作成
            CspParameters cp = new CspParameters();
            //キーコンテナ名を指定する
            cp.KeyContainerName = textBoxKeyContainer.Text;
            //CspParametersを指定してRSACryptoServiceProviderオブジェクトを作成
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cp);

            // 書庫ファイルをオープン
            using (ZipArchive arc = ZipFile.OpenRead(strInPath))
            {
                // 対称鍵と初期化ベクタを保持するバッファを取得
                string[] strKeys = new string[Enum.GetNames(typeof(AesKeys)).Length];

                // 対称鍵と初期化ベクタを取得
                foreach (AesKeys value in Enum.GetValues(typeof(AesKeys)))
                {
                    // 書庫ファイルからRSAで暗号化されたデータを取得
                    string strEntryName = Enum.GetName(typeof(AesKeys), value) + CryptographyExtName;
                    ZipArchiveEntry keyEntry = arc.GetEntry(strEntryName);
                    if (keyEntry == null)
                    {
                        throw new InvalidDataException(string.Format("\"{0}\" does not exist.", strEntryName));
                    }
                    // 復号
                    using (Stream stm = keyEntry.Open())
                    {
                        byte[] buf = new byte[BLOCK_SIZE];
                        int iReadLength = stm.Read(buf, 0, buf.Length);
                        strKeys[(int)value] = System.Text.Encoding.UTF8.GetString(rsa.Decrypt(buf, false));
                    }
                }

                // 書庫ファイルからAESで暗号化されたデータを検索
                //  暗号文ファイルは aesディレクトリの下に格納されているので、
                //  正規表現を使用して該当するファイルを検索
                string strSubDir = string.Format(@"{0}\/", CryptographySubDir);
                foreach (ZipArchiveEntry entry in arc.Entries)
                {
                    if (Regex.IsMatch(entry.FullName, strSubDir))
                    {
                        // 暗号文を復号
                        using (Stream stm = entry.Open())
                        {
                            AesCryptoServiceProvider csp = new AesCryptoServiceProvider();
                            csp.BlockSize = BLOCK_SIZE;
                            csp.KeySize = KEY_SIZE;
                            csp.Mode = CipherMode.CBC;
                            csp.Padding = PaddingMode.PKCS7;
                            csp.IV = Convert.FromBase64String(strKeys[(int)AesKeys.iv]);
                            csp.Key = Convert.FromBase64String(strKeys[(int)AesKeys.key]);

                            using (ICryptoTransform decryptor = csp.CreateDecryptor())
                            using (CryptoStream cs = new CryptoStream(stm, decryptor, CryptoStreamMode.Read))
                            using (DeflateStream ds = new DeflateStream(cs, CompressionMode.Decompress))
                            {
                                // 平文をストリームに書き出す
                                byte[] bytBuf = new byte[1024];
                                int len;
                                while ((len = ds.Read(bytBuf, 0, bytBuf.Length)) > 0)
                                {
                                    strmOut.Write(bytBuf, 0, len);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
