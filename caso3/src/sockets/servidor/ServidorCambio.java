package sockets.servidor;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sockets.conexion.Conexion;

public class ServidorCambio extends Conexion{

    private static final String[] ESTADOS_TEXTO = {"ENOFICINA","RECOGIDO","ENCLASIFICACION","DESPACHADO","ENENTREGA","ENTREGADO","DESCONOCIDO"};
    private static final int ENOFICINA = 0;
    private static final int RECOGIDO = 1;
    private static final int ENCLASIFICACION = 2;
    private static final int DESPACHADO = 3;
    private static final int ENENTREGA = 4;
    private static final int ENTREGADO = 5;
    private static final int DESCONOCIDO = 6;

    private PrivateKey llavePrivada;
    private Key llavePublica;
    private KeyAgreement keyAgree;
    private KeyPair dhKeyPair;
    private SecretKeySpec aesKey;
    private SecretKeySpec hmacKey;

    private static ConcurrentHashMap<String, Integer> paquetes = new ConcurrentHashMap<>();

    public ServidorCambio() throws Exception {
        super("servidor");
        inicializarPaquetes();
        this.llavePrivada = leerArchivoLlavePrivada("privateKey.key");
        this.llavePublica = leerArchivoLlavePublica("publicKey.key");

        // Inicializar Diffie-Hellman con parámetros de 1024 bits
        BigInteger p = new BigInteger("00c23dfb2c4c732c761b93d1ef2be85bbd36c72cecdaf76bed6837b4e8d85ec90804f806992e3b0063b76ed5d9f8c3428eed9d6a8602d3cd4ea46ee44a53a3c01a2efb3f5389c80ef1371b44345a9185e6f6db0e46467b59529f5d18c05d07175168172b68d65cc11ecaaed2510b3fb80063cecf3d2ea43aa23da1147c416dc2e7", 16);
        BigInteger g = BigInteger.valueOf(2);

        DHParameterSpec dhParams = new DHParameterSpec(p, g);
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(dhParams);
        this.dhKeyPair = keyPairGen.generateKeyPair();

        this.keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(dhKeyPair.getPrivate());
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

            socketCliente = socketServidor.accept();
             //Accept comienza el socket y espera una conexión desde un cliente

            DataInputStream entradaCliente = new DataInputStream(socketCliente.getInputStream());

            // Autenticación del reto
            String mensajeInicial = entradaCliente.readUTF();
            if ("SECINIT".equals(mensajeInicial)) {
                System.out.println("Cliente ha iniciado con SECINIT");

                int longitudRetoCifrado = entradaCliente.readInt();
                byte[] retoCifrado = new byte[longitudRetoCifrado];
                entradaCliente.readFully(retoCifrado);

                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, llavePrivada);
                byte[] retoDescifrado = cipher.doFinal(retoCifrado);
                String reto = new String(retoDescifrado);
                System.out.println("Reto recibido y descifrado (servidor): " + reto);
                salidaCliente.writeUTF(reto); // Responder con el reto descifrado

                // Enviar G, P y G^x
            BigInteger g = ((DHPublicKey) dhKeyPair.getPublic()).getParams().getG();
            BigInteger p = ((DHPublicKey) dhKeyPair.getPublic()).getParams().getP();
            BigInteger gx = ((DHPublicKey) dhKeyPair.getPublic()).getY();

            // Firmar los valores G, P y G^x
            Signature firma = Signature.getInstance("SHA1withRSA");
            firma.initSign(llavePrivada);

            firma.update(g.toByteArray());
            firma.update(p.toByteArray());
            firma.update(gx.toByteArray());

            byte[] firmaBytes = firma.sign();

            // Enviar G, P, G^x y la firma al cliente
            salidaCliente.writeUTF(g.toString());
            salidaCliente.writeUTF(p.toString());
            salidaCliente.writeUTF(gx.toString());
            salidaCliente.writeInt(firmaBytes.length);
            salidaCliente.write(firmaBytes);

            System.out.println("Valores y firma enviados al cliente.");

            // Recibir G^y del cliente
            int clientePublicKeyLength = entradaCliente.readInt();
            byte[] clientePublicKeyEnc = new byte[clientePublicKeyLength];
            entradaCliente.readFully(clientePublicKeyEnc);

            // Convertir G^y (clave pública del cliente) a una clave pública en el servidor
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            PublicKey clientePublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(clientePublicKeyEnc));

            // Calcular la llave secreta compartida (G^y)^x
            keyAgree.doPhase(clientePublicKey, true);
            byte[] sharedSecret = keyAgree.generateSecret();

            // Calcular digest SHA-512 de la llave secreta compartida
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecret);

            // Dividir el digest en dos partes de 256 bits
            byte[] aesKeyBytes = new byte[32];
            byte[] hmacKeyBytes = new byte[32];
            System.arraycopy(digest, 0, aesKeyBytes, 0, 32);
            System.arraycopy(digest, 32, hmacKeyBytes, 0, 32);

            // Crear llaves AES y HMAC
            aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA384");

            System.out.println("Llave AES generada: " + new BigInteger(1, aesKeyBytes).toString(16));
            System.out.println("Llave HMAC generada: " + new BigInteger(1, hmacKeyBytes).toString(16));

            }

            socketServidor.close();//Se finaliza la conexión con el cliente
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
    }

    public void manejarConsulta(DataInputStream entradaCliente, DataOutputStream salidaCliente) {
        try {
            // Leer identificador de usuario y paquete
            String uid = entradaCliente.readUTF();
            String paqueteId = entradaCliente.readUTF();

            // Buscar el estado en la tabla de paquetes
            int estado = paquetes.getOrDefault(uid + "_" + paqueteId, DESCONOCIDO);
            System.out.println("Consultando estado para " + uid + " y paquete " + paqueteId + ": " + estado);

            // Cifrar el estado usando AES CBC
            byte[] estadoBytes = String.valueOf(estado).getBytes("UTF-8");

            // Generar un IV aleatorio para el cifrado AES
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Inicializar el cifrador
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            byte[] estadoCifrado = cipher.doFinal(estadoBytes);

            // Generar el HMAC de los datos cifrados
            Mac mac = Mac.getInstance("HmacSHA384");
            mac.init(hmacKey);
            byte[] hmacFirma = mac.doFinal(estadoCifrado);

            // Enviar IV, estado cifrado, y HMAC al cliente
            salidaCliente.writeInt(iv.length);
            salidaCliente.write(iv);
            salidaCliente.writeInt(estadoCifrado.length);
            salidaCliente.write(estadoCifrado);
            salidaCliente.writeInt(hmacFirma.length);
            salidaCliente.write(hmacFirma);

            System.out.println("Estado cifrado y HMAC enviados al cliente.");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
