package decrypt12;

/*
 * 
 *** decrypt12.jar: Decrypts WhatsApp msgstore.db.crypt12 files. ***
 *
 * Author	:	TripCode
 * Copyright	:	Copyright (C) 2016
 * License	:	GPLv3
 * Status	:	Production
 * Version	:	1.0
 *
 */

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.Security;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
// import org.spongycastle.jce.provider.BouncyCastleProvider; // Android

public class decrypt12 {

	static {
		Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
		// Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1); // Android
	}

	public static void decrypt(String KeyFile, String C12File, String SQLFile) throws Exception {

		final File tempFile = new File(System.getProperty("java.io.tmpdir") + "/"
				+ (int) (System.currentTimeMillis() / 1000L) + "-msgstore.enc");

		if (!new File(KeyFile).isFile())
			quit("The specified input key file does not exist.");

		else if (new File(KeyFile).length() != 158)
			quit("The specified input key file is invalid.");

		else if (!new File(C12File).isFile())
			quit("The specified input crypt12 file does not exist.");

		InputStream KeyIn = new FileInputStream(KeyFile);
		InputStream WdbIn = new BufferedInputStream(new FileInputStream(C12File));

		byte[] KeyData = new byte[158];
		KeyIn.read(KeyData);
		byte[] T1 = new byte[32];
		System.arraycopy(KeyData, 30, T1, 0, 32);
		byte[] KEY = new byte[32];
		System.arraycopy(KeyData, 126, KEY, 0, 32);
		KeyIn.close();

		byte[] C12Data = new byte[67];
		WdbIn.read(C12Data);
		byte[] T2 = new byte[32];
		System.arraycopy(C12Data, 3, T2, 0, 32);
		byte[] IV = new byte[16];
		System.arraycopy(C12Data, 51, IV, 0, 16);

		if (!new String(T1, 0, T1.length, "ASCII").equals(new String(T2, 0, T2.length, "ASCII")))
			quit("Key file mismatch or crypt12 file is corrupt.");

		int InputLength = WdbIn.available();
		RandomAccessFile raf = new RandomAccessFile(tempFile, "rw");

		byte[] tempBuffer = new byte[1024];
		int I;

		while ((I = WdbIn.read(tempBuffer)) != -1)
			raf.write(tempBuffer, 0, I);
		raf.setLength(InputLength - 20);
		raf.close();
		WdbIn.close();

		InputStream PdbSt = new BufferedInputStream(new FileInputStream(tempFile));

		Cipher cipher;
		Security.addProvider(new BouncyCastleProvider());
		cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC"); // BouncyCastle
		// cipher = Cipher.getInstance("AES/GCM/NoPadding", "SC"); // SpongyCastle (Android)

		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV));
		CipherInputStream CipherStream = new CipherInputStream(PdbSt, cipher);

		InflaterInputStream CryptOutput = new InflaterInputStream(CipherStream, new Inflater(false));

		try {
			FileOutputStream InflateBuffer = new FileOutputStream(SQLFile);
			int N = 0;
			byte[] CryptBuffer = new byte[8192];

			while ((N = CryptOutput.read(CryptBuffer)) != -1) {
				InflateBuffer.write(CryptBuffer, 0, N);
			}
			InflateBuffer.close();

		} catch (IOException ex) {
			quit("Fatal error:" + ex);
		}

		CipherStream.close();
		tempFile.delete();

		InputStream SqlDB = new FileInputStream(SQLFile);

		byte[] SqlData = new byte[6];
		SqlDB.read(SqlData);
		byte[] MS = new byte[6];
		System.arraycopy(SqlData, 0, MS, 0, 6);
		SqlDB.close();

		if (!new String(MS, 0, MS.length, "ASCII").toLowerCase().equals("sqlite")) {
			new File(SQLFile).delete();
			quit("Decryption of crypt12 file has failed.");
		}

		else
			quit("Decryption of crypt12 file was successful.");
	}

	private static void quit(String Msg) {
		System.out.println(Msg);
		System.exit(0);
	}

	public static void main(String[] args) throws Exception {

		String outFile;
		if (args.length > 1 && args.length < 4) {
			if (args.length == 3)
				outFile = args[2];
			else
				outFile = "msgstore.db";
			decrypt(args[0], args[1], outFile);
		} else {
			System.out.println("\nWhatsApp Crypt12 Database Decrypter 1.0 Copyright (C) 2016 by TripCode");
			System.out.println("\tUsage: java -jar decrypt12.jar key msgstore.db.crypt12 msgstore.db\n");
		}
	}

}
