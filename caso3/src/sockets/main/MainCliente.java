package sockets.main;

import java.io.IOException;

import sockets.cliente.Cliente;

public class MainCliente {

    public static void main(String[] args) throws IOException
    {
        Cliente cli = new Cliente(); //Se crea el cliente

        System.out.println("Iniciando cliente\n");
        cli.startClient(); //Se inicia el cliente
    }
}
