import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.Base64;

public class FileEncryptor {
    public static void main(String[] args) throws Exception {
        // Gerar uma chave secreta AES
        SecretKey secretKey = generateKey();
        
        // Caminhos dos arquivos
        String inputFile = "texto_original.txt";
        String encryptedFile = "texto_encriptado.txt";
        String decryptedFile = "texto_desencriptado.txt";

        // Criptografar o arquivo
        encryptFile(inputFile, encryptedFile, secretKey);
        System.out.println("Arquivo criptografado salvo em: " + encryptedFile);

        // Descriptografar o arquivo
        decryptFile(encryptedFile, decryptedFile, secretKey);
        System.out.println("Arquivo descriptografado salvo em: " + decryptedFile);
    }

    // Método para gerar uma chave AES
    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // Chave de 128 bits
        return keyGen.generateKey();
    }

    // Método para criptografar o arquivo
    private static void encryptFile(String inputFile, String outputFile, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] inputBytes = readFile(inputFile);
        byte[] encryptedBytes = cipher.doFinal(inputBytes);

        writeFile(outputFile, Base64.getEncoder().encode(encryptedBytes));
    }

    // Método para descriptografar o arquivo
    private static void decryptFile(String inputFile, String outputFile, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] encryptedBytes = Base64.getDecoder().decode(readFile(inputFile));
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        writeFile(outputFile, decryptedBytes);
    }

    // Método para ler o conteúdo de um arquivo
    private static byte[] readFile(String filePath) throws IOException {
        return new FileInputStream(filePath).readAllBytes();
    }

    // Método para escrever conteúdo em um arquivo
    private static void writeFile(String filePath, byte[] content) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(content);
        }
    }
}
