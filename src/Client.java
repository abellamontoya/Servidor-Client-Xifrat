import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class Client {
    private static Socket socket;
    private static ObjectOutputStream out;
    private static ObjectInputStream in;
    private static PublicKey serverPublicKey;

    public static void main(String[] args) {
        try {
            socket = new Socket("localhost", 12345);
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());
            byte[] publicKeyBytes = (byte[]) in.readObject();
            serverPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String message;
            while (true) {
                System.out.print("Tú: ");
                message = reader.readLine();
                if (message.equals("/close")) {
                    out.writeObject(encrypt(message.getBytes(), serverPublicKey));
                    out.flush();
                    break;
                }
                out.writeObject(encrypt(message.getBytes(), serverPublicKey));
                out.flush();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                in.close();
                out.close();
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }
}
