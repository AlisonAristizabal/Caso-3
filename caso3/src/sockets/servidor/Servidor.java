package sockets.servidor;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.function.Supplier;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import sockets.conexion.Conexion;


public class Servidor extends Conexion {

    private static final String[] ESTADOS_TEXTO = {"ENOFICINA","RECOGIDO","ENCLASIFICACION","DESPACHADO","ENENTREGA","ENTREGADO","DESCONOCIDO"};
    private static final int ENOFICINA = 0;
    private static final int RECOGIDO = 1;
    private static final int ENCLASIFICACION = 2;
    private static final int DESPACHADO = 3;
    private static final int ENENTREGA = 4;
    private static final int ENTREGADO = 5;
    private static final int DESCONOCIDO = 6;

    private PrivateKey llavePrivada;
    private PublicKey llavePublica;
    private static final BigInteger p = new BigInteger("00c23dfb2c4c732c761b93d1ef2be85bbd36c72cecdaf76bed6837b4e8d85ec90804f806992e3b0063b76ed5d9f8c3428eed9d6a8602d3cd4ea46ee44a53a3c01a2efb3f5389c80ef1371b44345a9185e6f6db0e46467b59529f5d18c05d07175168172b68d65cc11ecaaed2510b3fb80063cecf3d2ea43aa23da1147c416dc2e7", 16);
    private static final BigInteger g = BigInteger.valueOf(2);
    
    private static HashMap<String, Integer> paquetes = new HashMap<>();

    public Servidor() throws Exception {
        super("servidor");
        inicializarPaquetes();
        this.llavePrivada = leerArchivoLlavePrivada("privateKey.key");
        this.llavePublica = leerArchivoLlavePublica("publicKey.key");
    }

    private void inicializarPaquetes() {
        // Añadir 32 entradas en la tabla de paquetes
        for (int i = 1; i <= 32; i++) {
            paquetes.put("cliente" + i + "_paquete" + i, i % 6); // Ciclo en los estados para ejemplo
        }
    }

    private static PrivateKey leerArchivoLlavePrivada(String pathPrivado) throws Exception {
        byte[] keyBytesPrivada = Files.readAllBytes(Paths.get(pathPrivado));
        PKCS8EncodedKeySpec specPrivada = new PKCS8EncodedKeySpec(keyBytesPrivada);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(specPrivada);
    }

    private static PublicKey leerArchivoLlavePublica(String pathPublico) throws Exception {
        byte[] keyBytesPublica = Files.readAllBytes(Paths.get(pathPublico));
        X509EncodedKeySpec specPublica = new X509EncodedKeySpec(keyBytesPublica);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(specPublica);
    }        

    public void startServer(Supplier<Boolean> isRunning) throws Exception {
        System.out.println("Servidor iniciado y esperando conexiones...");

        while (isRunning.get()) { // Check if the server should keep running
            try {
                socketCliente = socketServidor.accept();
                System.out.println("Cliente conectado.");
                // Create a new thread for each connected client
                new Thread(new ClienteHandler(socketCliente)).start();
            } catch (IOException e) {
                e.printStackTrace();
                if (!isRunning.get()) { // Stop accepting new connections if the server is shutting down
                    break;
                }
            }
        }
    }

    private class ClienteHandler implements Runnable {
        private DataInputStream entradaCliente;
        private DataOutputStream salidaServidor;
        private KeyAgreement keyAgree;
        private SecretKeySpec aesKey;
        private SecretKeySpec hmacKey;
        private KeyPair dhKeyPair;

        public ClienteHandler(Socket socketCliente) throws Exception {
            this.entradaCliente = new DataInputStream(socketCliente.getInputStream());
            this.salidaServidor = new DataOutputStream(socketCliente.getOutputStream());
            generarClavesDiffieHellman();
        }

        private void generarClavesDiffieHellman() throws Exception {
            // Configurar DH y generar claves individuales para cada cliente
            DHParameterSpec dhParams = new DHParameterSpec(p, g);
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(dhParams);
            this.dhKeyPair = keyPairGen.generateKeyPair();
            
            this.keyAgree = KeyAgreement.getInstance("DH");
            keyAgree.init(dhKeyPair.getPrivate());
        }

        @Override
        public void run() {
            try {
                manejarAutenticacion();
                manejarConsulta();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    entradaCliente.close();
                    salidaServidor.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        private void manejarAutenticacion() throws Exception {
            long startReto = System.nanoTime();

            String mensajeInicial = entradaCliente.readUTF();
            if ("SECINIT".equals(mensajeInicial)) {
                System.out.println("Cliente ha iniciado con SECINIT");

                int longitudRetoCifrado = entradaCliente.readInt();
                byte[] retoCifrado = new byte[longitudRetoCifrado];
                entradaCliente.readFully(retoCifrado);

                long startAsimetrico = System.nanoTime();
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, llavePrivada);
                byte[] retoDescifrado = cipher.doFinal(retoCifrado);
                long endAsimetrico = System.nanoTime();
                System.out.println("Tiempo para cifrar asimétricamente: " + (endAsimetrico - startAsimetrico) + " nanosegundos");

                String reto = new String(retoDescifrado);
                long endReto = System.nanoTime();
                System.out.println("Tiempo para responder el reto: " + (endReto - startReto) + " nanosegundos");

                System.out.println("Reto recibido y descifrado (servidor): " + reto);
                salidaServidor.writeUTF(reto);

                long startGPx = System.nanoTime();

                BigInteger g = ((DHPublicKey) dhKeyPair.getPublic()).getParams().getG();
                BigInteger p = ((DHPublicKey) dhKeyPair.getPublic()).getParams().getP();
                BigInteger gx = ((DHPublicKey) dhKeyPair.getPublic()).getY();

                long endGPx = System.nanoTime();
                System.out.println("Tiempo para generar G, P y Gx: " + (endGPx - startGPx) + " nanosegundos");

                // Firmar los valores G, P y G^x
                Signature firma = Signature.getInstance("SHA1withRSA");
                firma.initSign(llavePrivada);
                firma.update(g.toByteArray());
                firma.update(p.toByteArray());
                firma.update(gx.toByteArray());
                byte[] firmaBytes = firma.sign();

                salidaServidor.writeUTF(g.toString());
                salidaServidor.writeUTF(p.toString());
                salidaServidor.writeUTF(gx.toString());
                salidaServidor.writeInt(firmaBytes.length);
                salidaServidor.write(firmaBytes);

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

                byte[] aesKeyBytes = new byte[32];
                byte[] hmacKeyBytes = new byte[32];
                System.arraycopy(digest, 0, aesKeyBytes, 0, 32);
                System.arraycopy(digest, 32, hmacKeyBytes, 0, 32);

                aesKey = new SecretKeySpec(aesKeyBytes, "AES");
                hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA384");

                System.out.println("Llave AES generada: " + new BigInteger(1, aesKeyBytes).toString(16));
                System.out.println("Llave HMAC generada: " + new BigInteger(1, hmacKeyBytes).toString(16));
            }
        }

        private synchronized void manejarConsulta() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
            long startConsulta = System.nanoTime();
            String uid = entradaCliente.readUTF();
            String paqueteId = entradaCliente.readUTF();

            int estado = paquetes.getOrDefault(uid + "_" + paqueteId, DESCONOCIDO);
            System.out.println("Consultando estado para " + uid + " y paquete " + paqueteId + ": " + estado);

            long endConsulta = System.nanoTime();
            System.out.println("Tiempo para verificar la consulta: " + (endConsulta - startConsulta) + " nanosegundos");

            byte[] estadoBytes = String.valueOf(estado).getBytes("UTF-8");
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            long startSimetrico = System.nanoTime();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            byte[] estadoCifrado = cipher.doFinal(estadoBytes);
            long endSimetrico = System.nanoTime();
            System.out.println("Tiempo para cifrar simétricamente: " + (endSimetrico - startSimetrico) + " nanosegundos");

            Mac mac = Mac.getInstance("HmacSHA384");
            mac.init(hmacKey);
            byte[] hmacFirma = mac.doFinal(estadoCifrado);

            salidaServidor.writeInt(iv.length);
            salidaServidor.write(iv);
            salidaServidor.writeInt(estadoCifrado.length);
            salidaServidor.write(estadoCifrado);
            salidaServidor.writeInt(hmacFirma.length);
            salidaServidor.write(hmacFirma);

            System.out.println("Estado cifrado y HMAC enviados al cliente.");
        }
    }

    public void closeServer() throws IOException {
        if (socketServidor != null && !socketServidor.isClosed()) {
            socketServidor.close();
            System.out.println("El servidor ha sido cerrado.");
        }
    }
}
