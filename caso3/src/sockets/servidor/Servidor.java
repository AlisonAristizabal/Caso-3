package sockets.servidor;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;

import sockets.conexion.Conexion;

public class Servidor extends Conexion{

    private static final String[] ESTADOS_TEXTO = {"ENOFICINA","RECOGIDO","ENCLASIFICACION","DESPACHADO","ENENTREGA","ENTREGADO","DESCONOCIDO"};
    private static final int ENOFICINA = 0;
    private static final int RECOGIDO = 1;
    private static final int ENCLASIFICACION = 2;
    private static final int DESPACHADO = 3;
    private static final int ENENTREGA = 4;
    private static final int ENTREGADO = 5;
    private static final int DESCONOCIDO = 6;

    private Key llavePrivada;
    private Key llavePublica;

    private static HashMap<String, Integer> paquetes = new HashMap<>();

    public Servidor() throws IOException {
        super("servidor");
        inicializarPaquetes();
    }

    private void inicializarPaquetes() {
        // Asociar identificadores de cliente y paquete con estados numéricos
        paquetes.put("cliente1_paquete1", ENOFICINA);
        paquetes.put("cliente1_paquete2", RECOGIDO);
        // Puedes agregar más paquetes aquí
    }

    private static PrivateKey leerArchivoLlavePrivada (String pathPrivado) throws Exception{

        byte[] keyBytesPrivada = Files.readAllBytes(Paths.get(pathPrivado));

        // Decodificación llaves
        PKCS8EncodedKeySpec specPrivada = new PKCS8EncodedKeySpec(keyBytesPrivada);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(specPrivada);
    }

    private static PublicKey leerArchivoLlavePublica (String pathPublico) throws Exception{

        byte[] keyBytesPublica = Files.readAllBytes(Paths.get(pathPublico));

        // Decodificación llaves
        PKCS8EncodedKeySpec specPublica = new PKCS8EncodedKeySpec(keyBytesPublica);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(specPublica);
    }

    public void startServer()//Método para iniciar el servidor
    {
        try
        {
            System.out.println("Esperando..."); //Esperando conexión

            socketCliente = socketServidor.accept(); //Accept comienza el socket y espera una conexión desde un cliente

            System.out.println("Cliente en línea");

            //Se obtiene el flujo de salida del cliente para enviarle mensajes
            salidaCliente = new DataOutputStream(socketCliente.getOutputStream());

            //Se le envía un mensaje al cliente usando su flujo de salida
            salidaCliente.writeUTF("Petición recibida y aceptada");

            //Se obtiene el flujo entrante desde el cliente
            BufferedReader entrada = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));

            while((mensajeServidor = entrada.readLine()) != null) //Mientras haya mensajes desde el cliente
            {
                //Se muestra por pantalla el mensaje recibido
                System.out.println(mensajeServidor);
            }

            System.out.println("Fin de la conexión");

            socketServidor.close();//Se finaliza la conexión con el cliente
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
    }
}
