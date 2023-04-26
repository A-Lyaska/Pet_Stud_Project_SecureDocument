package com.example.securedocumentexchange.security;

import com.sshtools.common.publickey.InvalidPassphraseException;
import com.sshtools.common.publickey.SshKeyUtils;
import com.sshtools.common.ssh.components.SshPublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class SecurityService {
    PublicKey publicKey;

    PrivateKey privateKey;

    public String encryptMessage(String message, File publicKeyFile) throws IOException, GeneralSecurityException {
        //byte[] publicKeyBytes = Base64.getDecoder().decode(new FileInputStream(publicKeyFile).readAllBytes());
        SshPublicKey sshPublicKey = SshKeyUtils.getPublicKey(publicKeyFile);

        publicKey = sshPublicKey.getJCEPublicKey();

        Key aesKey = generateAes(128);

        IvParameterSpec iv = generateIv(aesKey.getEncoded().length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv.getIV()));

        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedAesKey = cipher.doFinal(aesKey.getEncoded());

        byte[] outputMessageWithKey = new byte[encryptedBytes.length + encryptedAesKey.length + iv.getIV().length];

        System.arraycopy(iv.getIV(), 0, outputMessageWithKey,0, iv.getIV().length);

        System.arraycopy(encryptedAesKey, 0, outputMessageWithKey, iv.getIV().length, encryptedAesKey.length);

        System.arraycopy(encryptedBytes, 0, outputMessageWithKey, iv.getIV().length + encryptedAesKey.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(outputMessageWithKey);
    }

    private SecretKeySpec generateAes(int keySize) {
        byte[] aesByte = new byte[keySize / 8];

        SecureRandom secureRandom = new SecureRandom();

        secureRandom.nextBytes(aesByte);

        return new SecretKeySpec(aesByte, "AES");
    }

    private IvParameterSpec generateIv(int keySize) {
        byte[] ivByte = new byte[keySize];

        SecureRandom secureRandom = new SecureRandom();

        secureRandom.nextBytes(ivByte);

        return new IvParameterSpec(ivByte);
    }

    public String decryptMessage(String message, File privateKeyFile) throws IOException, GeneralSecurityException, InvalidPassphraseException {
        byte[] encodedBytes = Base64.getDecoder().decode(message);

        byte[] iv = Arrays.copyOfRange(encodedBytes, 0, 16);

        byte[] aesKeyEnc = Arrays.copyOfRange(encodedBytes, 16, 512+16);

        byte[] dataEnc = Arrays.copyOfRange(encodedBytes, 512+16, encodedBytes.length);

        privateKey = SshKeyUtils.getPrivateKey(privateKeyFile, "").getPrivateKey().getJCEPrivateKey();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");

        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decodedAesKey = cipher.doFinal(aesKeyEnc);

        Key aesKey = new SecretKeySpec(decodedAesKey, "AES");

        cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));

        byte[] decodedData = cipher.doFinal(dataEnc);

        String data = new String(decodedData, "UTF-8");

        return data;
    }
//Сначала метод получает имя файла документа и создает новое имя файла для зашифрованного файла, добавляя расширение ".sde".
//
//Затем метод использует библиотеку SshKeyUtils для получения открытого ключа RSA из файла, который будет использоваться для шифрования документа.
//
//Полученный открытый ключ используется для инициализации шифра RSA для шифрования данных.
//
//Затем метод открывает входной поток для чтения данных из исходного документа и выходной поток для записи зашифрованных данных в файл.
//
//Метод читает данные из исходного файла в буфер и вызывает метод doFinal () на объекте шифра RSA для шифрования данных в буфере. Зашифрованные данные записываются в выходной файл.
//
//Это продолжается, пока все данные из исходного файла не будут зашифрованы и записаны в выходной файл.
//
//Метод может выкинуть исключения, если возникают ошибки при чтении и записи данных, или при инициализации шифра RSA.
    public void encryptDocument(File document, File publicKeyFile) throws IOException, GeneralSecurityException {
        // Получаем имя файла
        String filename = document.getName();
        // Создаем имя зашифрованного файла
        String encryptedFilename = filename + ".sde";
        // Создаем файл зашифрованного документа в той же директории, где и оригинальный документ
        File encryptedFile = new File(document.getParent(), encryptedFilename);

        // Получаем открытый ключ из файла
        SshPublicKey sshPublicKey = SshKeyUtils.getPublicKey(publicKeyFile);
        publicKey = sshPublicKey.getJCEPublicKey();

        // Инициализируем шифрование с помощью алгоритма RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Читаем файл и шифруем его содержимое порциями по 1024 байта
        try (FileInputStream in = new FileInputStream(document); FileOutputStream out = new FileOutputStream(encryptedFile)) {
            byte[] buf = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(buf)) != -1) {
                // Шифруем текущую порцию данных
                byte[] cipherData = cipher.doFinal(buf, 0, bytesRead);
                // Записываем зашифрованную порцию в файл
                out.write(cipherData);
            }
        }
    }

    public void decryptDocument(File document, File privateKeyFile) throws IOException, GeneralSecurityException, InvalidPassphraseException {
        // Проверяем, что файл с зашифрованным документом существует и является файлом
        if (!document.exists() || !document.isFile()) {
            throw new IOException("Invalid input file");
        }

        // Получаем зашифрованный файл и его расширение
        String encryptedFilename = document.getName();
        String extension = ".sde";

        // Проверяем, что файл имеет верное расширение
        if (!encryptedFilename.endsWith(extension)) {
            throw new IOException("Invalid input file extension");
        }

        // Получаем расширение файла с документом
        String filename = encryptedFilename.substring(0, encryptedFilename.length() - extension.length());

        // Проверяем, что файл закрытого ключа существует и является файлом
        if (!privateKeyFile.exists() || !privateKeyFile.isFile()) {
            throw new IOException("Invalid secret key file");
        }

        // Получаем закрытый ключ
        privateKey = SshKeyUtils.getPrivateKey(privateKeyFile, "").getPrivateKey().getJCEPrivateKey();

        // Получаем данные из зашифрованного файла
        byte[] encryptedData = Files.readAllBytes(document.toPath());

        // Расшифровываем симметричный ключ с помощью закрытого ключа
        byte[] aesKeyEnc = Arrays.copyOfRange(encryptedData, 16, 512);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyDec = cipher.doFinal(aesKeyEnc);

        // Расшифровываем данные с помощью симметричного ключа
        byte[] iv = Arrays.copyOfRange(encryptedData, 0, 16);
        byte[] dataEnc = Arrays.copyOfRange(encryptedData, 512+16, encryptedData.length);
        Key aesKey = new SecretKeySpec(aesKeyDec, "AES");
        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        byte[] dataDec = cipher.doFinal(dataEnc);

        // Записываем расшифрованные данные в файл
        File decryptedFile = new File(document.getParentFile(), filename);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(decryptedFile))) {
            writer.write(Arrays.toString(dataDec));
        }
    }

    public void signDocument(File document, File privateKey) throws IOException, GeneralSecurityException, InvalidPassphraseException {

    }

    public boolean verifyDocument(File document, File signFile, File publicKey) throws IOException, GeneralSecurityException {
        return false;
    }
}
