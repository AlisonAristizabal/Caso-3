package sockets.main;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import sockets.cliente.Cliente;

public class MainCliente {

    public static void main(String[] args) {
        int numClientes = 3; // Número de clientes a ejecutar concurrentemente
        ExecutorService executor = Executors.newFixedThreadPool(numClientes);

        for (int i = 0; i < numClientes; i++) {
            int clienteId = i + 1;
            String clienteIdentificador = "cliente" + clienteId;
            String paqueteId = "paquete" + clienteId;

            executor.execute(() -> {
                try {
                    // Crear el cliente con identificador y paquete específicos
                    Cliente cli = new Cliente(clienteIdentificador, paqueteId);
                    System.out.println("Iniciando " + clienteIdentificador + " buscando " + paqueteId);
                    cli.startClient(); // Iniciar el cliente
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        }

        executor.shutdown();
    }
}
