package sockets.conexion;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Conexion {

    private final int PUERTO = 1234;
    private final String HOST = "localhost";
    protected String mensajeServidor;
    protected ServerSocket socketServidor;
    protected Socket socketCliente;
    protected DataOutputStream salidaServidor, salidaCliente;

    public Conexion(String tipo) throws IOException {

        if (tipo.equalsIgnoreCase("servidor")) {
            socketServidor = new ServerSocket(PUERTO);
            // No se configura el socketCliente ni el OutputStream del servidor aquí
        } else {
            socketCliente = new Socket(HOST, PUERTO);
            salidaCliente = new DataOutputStream(socketCliente.getOutputStream());
        }
    }
}
