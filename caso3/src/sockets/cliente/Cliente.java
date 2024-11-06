package sockets.cliente;

import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sockets.conexion.Conexion;

public class Cliente extends Conexion{

    private static final String[] ESTADOS_TEXTO = {
        "ENOFICINA", "RECOGIDO", "ENCLASIFICACION", "DESPACHADO", "ENENTREGA", "ENTREGADO", "DESCONOCIDO"
    };
    
    private PublicKey llavePublica;
    SecureRandom secureRandom = new SecureRandom();
    private KeyAgreement keyAgree;
    private SecretKeySpec aesKey;
    private SecretKeySpec hmacKey;
    private DataInputStream entradaServidor;
    private String clienteId;
    private String paqueteId;

    public Cliente(String clienteId, String paqueteId) throws IOException {
        super("cliente");
        this.clienteId = clienteId;
        this.paqueteId = paqueteId;
        
    }

    private static PublicKey leerArchivoLlavePublica(String pathPublico) throws Exception {
        try {
            byte[] keyBytesPublica = Files.readAllBytes(Paths.get(pathPublico));
            // Cambia PKCS8EncodedKeySpec por X509EncodedKeySpec para las claves públicas
            X509EncodedKeySpec specPublica = new X509EncodedKeySpec(keyBytesPublica);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(specPublica);
        } catch (Exception e) {
            System.err.println("Error al leer o generar la clave pública: " + e.getMessage());
            throw e;
        }
    }
    

    public void startClient() //Método para iniciar el cliente
    {
        try {

            this.llavePublica = leerArchivoLlavePublica("publicKey.key");

            //Enviar mensaje inicial "SECINIT" al servidor
            salidaCliente.writeUTF("SECINIT");

            entradaServidor = new DataInputStream(socketCliente.getInputStream());

            BigInteger reto = new BigInteger(128, secureRandom);
            System.out.println("Reto generado (cliente): " + reto);
            
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, llavePublica);
            byte[] retoCifrado = cipher.doFinal(String.valueOf(reto).getBytes());

            // Enviar el reto cifrado al servidor
            salidaCliente.writeInt(retoCifrado.length);  // Primero enviamos el tamaño del reto cifrado
            salidaCliente.write(retoCifrado);  // Luego enviamos el reto cifrado

            DataInputStream entradaServidor = new DataInputStream(socketCliente.getInputStream());
            String retoDescifrado = entradaServidor.readUTF();

            // Verificar si el reto recibido coincide con el original
            if (retoDescifrado.equals(String.valueOf(reto))) {
                System.out.println("Verificación exitosa: el reto coincide.");
            } else {
                System.out.println("Error de verificación: el reto no coincide.");
                socketCliente.close();
            }

            // Recibir G, P, G^x y la firma
            BigInteger g = new BigInteger(entradaServidor.readUTF());
            BigInteger p = new BigInteger(entradaServidor.readUTF());
            BigInteger gx = new BigInteger(entradaServidor.readUTF());

            int firmaLength = entradaServidor.readInt();
            byte[] firmaBytes = new byte[firmaLength];
            entradaServidor.readFully(firmaBytes);

            // Verificar la firma con la llave pública del servidor
            Signature firma = Signature.getInstance("SHA1withRSA");
            firma.initVerify(llavePublica);

            firma.update(g.toByteArray());
            firma.update(p.toByteArray());
            firma.update(gx.toByteArray());

            boolean esValida = firma.verify(firmaBytes);
            if (esValida) {
                System.out.println("Firma verificada: los valores de G, P y G^x son auténticos.");
                
                //Diffie-Hellman valores recibidos
                DHParameterSpec dhParams = new DHParameterSpec(p, g);
                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
                keyPairGen.initialize(dhParams);
                KeyPair dhKeyPair = keyPairGen.generateKeyPair();


            } else {
                System.out.println("Error de verificación: los valores de G, P y G^x no son válidos.");
                socketCliente.close();
            }

            // Si la verificación es exitosa, generar G^y y enviar al servidor
            DHParameterSpec dhParams = new DHParameterSpec(p, g);
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(dhParams);
            KeyPair dhKeyPair = keyPairGen.generateKeyPair();

            keyAgree = KeyAgreement.getInstance("DH");
            keyAgree.init(dhKeyPair.getPrivate());

            // Obtener G^y y enviarla al servidor
            byte[] gyBytes = dhKeyPair.getPublic().getEncoded();
            salidaCliente.writeInt(gyBytes.length);
            salidaCliente.write(gyBytes);

            // generar la llave secreta compartida
            BigInteger gxBigInt = new BigInteger(gx.toByteArray()); 
            DHPublicKeySpec dhPublicSpec = new DHPublicKeySpec(gxBigInt, p, g);
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            PublicKey serverPublicKey = keyFactory.generatePublic(dhPublicSpec);
            keyAgree.doPhase(serverPublicKey, true);

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

            solicitarEstadoPaquete(clienteId, paqueteId);
            socketCliente.close();

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public void solicitarEstadoPaquete(String uid, String paqueteId) {
        try {
            // Enviar identificador de usuario y paquete
            salidaCliente.writeUTF(uid);
            salidaCliente.writeUTF(paqueteId);

            // Recibir IV
            int ivLength = entradaServidor.readInt();
            byte[] iv = new byte[ivLength];
            entradaServidor.readFully(iv);

            // Recibir estado cifrado
            int estadoCifradoLength = entradaServidor.readInt();
            byte[] estadoCifrado = new byte[estadoCifradoLength];
            entradaServidor.readFully(estadoCifrado);

            // Recibir HMAC
            int hmacLength = entradaServidor.readInt();
            byte[] hmacFirma = new byte[hmacLength];
            entradaServidor.readFully(hmacFirma);

            // Verificar el HMAC
            Mac mac = Mac.getInstance("HmacSHA384");
            mac.init(hmacKey);
            byte[] hmacCalculado = mac.doFinal(estadoCifrado);

            if (Arrays.equals(hmacFirma, hmacCalculado)) {
                System.out.println("HMAC verificado correctamente.");

                // Descifrar el estado
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
                byte[] estadoDescifrado = cipher.doFinal(estadoCifrado);

                int estado = Integer.parseInt(new String(estadoDescifrado, "UTF-8"));
                System.out.println("Estado del paquete: " + ESTADOS_TEXTO[estado]);
            } else {
                System.out.println("Error: HMAC no coincide. Los datos pueden haber sido manipulados.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
