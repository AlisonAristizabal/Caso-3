package sockets.cliente;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import sockets.conexion.Conexion;

public class Cliente extends Conexion{

    private Key llavePublica;

    public Cliente() throws IOException {
        super("cliente");
    }

    private static PublicKey leerArchivoLlavePublica (String pathPublico) throws Exception{

        byte[] keyBytesPublica = Files.readAllBytes(Paths.get(pathPublico));

        // Decodificación llaves
        PKCS8EncodedKeySpec specPublica = new PKCS8EncodedKeySpec(keyBytesPublica);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(specPublica);
    }

    public void startClient() //Método para iniciar el cliente
    {
        try {

            llavePublica = leerArchivoLlavePublica("publicKey.key");

            //Enviar mensaje inicial "SECINIT" al servidor
            salidaServidor.writeUTF("SECINIT");

            salidaServidor = new DataOutputStream(socketCliente.getOutputStream());
            
            socketCliente.close();

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
