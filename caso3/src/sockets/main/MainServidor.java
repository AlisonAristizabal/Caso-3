package sockets.main;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.EnumSet;
import java.util.Scanner;
import java.util.Set;

import sockets.servidor.Servidor;

public class MainServidor {

    private static volatile boolean isRunning = true; // Variable para controlar la ejecución del servidor

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        int opcion;

        do {
            System.out.println("===== Sistema de rastreo de paquetes =====");
            System.out.println("1. Generar pareja de llaves");
            System.out.println("2. Ejecutar los delegados");
            System.out.println("3. Salir");
            System.out.print("Seleccione una opción: ");
            opcion = scanner.nextInt();
            scanner.nextLine();

            switch (opcion) {
                case 1:
                    generarParejaLlaves();
                    break;
                case 2:
                    ejecutarDelegados();
                    break;
                case 3:
                    System.out.println("Saliendo del programa...");
                    isRunning = false; // Detener el servidor si está corriendo
                    break;
                default:
                    System.out.println("Opción no válida. Intente de nuevo.");
            }
        } while (opcion != 3);

        scanner.close();
    }

    private static void generarParejaLlaves() {
        try {
            // Generar el par de llaves RSA
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024); // Llave de 1024 bits
            KeyPair pair = keyGen.generateKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();

            // Guardar la llave pública en un archivo
            try (FileOutputStream fos = new FileOutputStream("publicKey.key")) {
                fos.write(publicKey.getEncoded());
                System.out.println("Llave pública guardada en 'publicKey.key'");
            }

            // Guardar la llave privada en un archivo
            try (FileOutputStream fos = new FileOutputStream("privateKey.key")) {
                fos.write(privateKey.getEncoded());
                System.out.println("Llave privada guardada en 'privateKey.key'");
                ajustarPermisosArchivoPrivado("privateKey.key");
            }

            System.out.println("Pareja de llaves generada y guardada exitosamente.");
        } catch (NoSuchAlgorithmException | IOException e) {
            System.err.println("Error generando las llaves: " + e.getMessage());
        }
    }

    // Función para ajustar permisos de llaves privadas
    private static void ajustarPermisosArchivoPrivado(String pathFile) {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (!os.contains("win")) { // Solo intenta ajustar permisos en sistemas no Windows
                Set<PosixFilePermission> permisos = EnumSet.of(PosixFilePermission.OWNER_READ);
                Path privateKeyPath = Paths.get(pathFile);
                Files.setPosixFilePermissions(privateKeyPath, permisos);
                System.out.println("Permisos ajustados correctamente para " + pathFile);
            }
        } catch (IOException e) {
            System.err.println("Error ajustando permisos: " + e.getMessage());
        }
    }
    

    private static void ejecutarDelegados() throws Exception {
        Servidor serv = new Servidor(); // Create the server instance
    
        // Start a thread for the server to handle client connections
        Thread serverThread = new Thread(() -> {
            try {
                System.out.println("Iniciando servidor\n");
                serv.startServer(() -> isRunning); // Pass the isRunning supplier to control server shutdown
            } catch (Exception e) {
                System.err.println("Error en el servidor: " + e.getMessage());
            }
        });
    
        serverThread.start();
    
        // Thread to control server shutdown
        new Thread(() -> {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Escriba 'cerrar' para detener el servidor.");
            while (isRunning) {
                String comando = scanner.nextLine();
                if ("cerrar".equalsIgnoreCase(comando)) {
                    isRunning = false; // Set isRunning to false to stop the server
                    try {
                        serv.closeServer(); // Close the server safely
                        System.out.println("Servidor detenido.");
                    } catch (IOException e) {
                        System.err.println("Error al cerrar el servidor: " + e.getMessage());
                    }
                    break;
                }
            }
            scanner.close();
        }).start();
    }    
}
