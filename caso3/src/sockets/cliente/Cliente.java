package sockets.cliente;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import sockets.conexion.Conexion;

public class Cliente extends Conexion{

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
        try
        {
            //Flujo de datos hacia el servidor
            salidaServidor = new DataOutputStream(socketCliente.getOutputStream());

            //Se enviarán dos mensajes
            for (int i = 0; i < 2; i++)
            {
                //Se escribe en el servidor usando su flujo de datos
                salidaServidor.writeUTF("Este es el mensaje número " + (i+1) + "\n");
            }

            socketCliente.close();//Fin de la conexión

        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
    }
}
