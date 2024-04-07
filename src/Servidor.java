import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class Servidor {
    private static ServerSocket serverSocket;
    private static Socket clientSocket;
    private static ObjectInputStream in;
    private static PrivateKey privateKey;

    public static void main(String[] args) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            privateKey = keyPair.getPrivate();
            serverSocket = new ServerSocket(12345);
            System.out.println("Servidor esperando conexiones...");
            clientSocket = serverSocket.accept();
            System.out.println("Cliente conectado.");
            in = new ObjectInputStream(clientSocket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            out.writeObject(keyPair.getPublic().getEncoded());
            out.flush();
            while (true) {
                byte[] encryptedMessage = (byte[]) in.readObject();
                String decryptedMessage = new String(decrypt(encryptedMessage, privateKey));
                System.out.println("Mensaje Encriptado: " + bytesToHex(encryptedMessage));
                System.out.println("Cliente: " + decryptedMessage);
                if (decryptedMessage.equals("/close")) {
                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                in.close();
                clientSocket.close();
                serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static byte[] decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
}
