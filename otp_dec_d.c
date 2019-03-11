/**************************************************************************************
 * Author: Xiaoqiong Dong
 * Date: Nov 29, 2018
 * Description: This program takes receives ciphertext and key from the client, decript 
 * 		the ciphertext, and send the plaintext back to the client.
 *************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <signal.h>

//Global variables
int childFinished = 0; //1: some child process has finished; 0: no child process finished

void error(const char* msg){ perror(msg); exit(1); } //Error function to report issues

/********************************************************************************************
 * Function: encode
 * Description: This function uses one-time pad method to decode ciphertext with key
 * Arguments: ciphertext: const char*, string of ciphertext
 * 	      key: const char*, string of key
 * 	      decodedMsg: char*, a char* to the string that will store decoded message
 * Precondition: ciphertext and key all have valid characters and lengths. The memory of
 * 		 of decodedMsg is allocated and initialized to '\0'.
 * Postcondition: decodedMsg is modified to the deciphered message from ciphertext using key
 * *****************************************************************************************/
void decode(const char* ciphertext, const char* key, char* decodedMsg)
{
	int i, lenCiphertext = strlen(ciphertext), c, k, d;
	for ( i = 0; i < lenCiphertext; i++)
	{
		// get the numerical value of char of ciphertext
		c = (int)ciphertext[i] - 65;
		if (c < 0) //space
			c = 26;
		// get the numerical value of char of key
		k = (int)key[i] - 65;
		if (k < 0) //space
			k = 26;
		//get the ASCII of char of decodedMsg
		d = (c - k + 27) % 27 + 65;
		if (d > 90) //space
			d = 32;
		decodedMsg[i] = (char)d;
	}

}


/***********************************************************************************************
 * Function: writeToSocket
 * Description: This function writes a string to a socket. If the length of the string is longer
 * 		than 1024, then the string is sent in chunks of 1024 chars.
 * Arguments: socketFD: int, the file descriptor of the socket that the string is written to
 * 	      text: char*, a pointer to the string that will be written to socket
 * 	      ntext: int, the length of text
 * Precondition: N/A
 * Postcondition: the whole string is written to socket
 * **********************************************************************************************/
void writeToSocket(int socketFD, char* text, int ntext)
{
	int charsWritten, leftBehind;
	while (ntext > 0)
	{	
		if (ntext >= 1024)
			leftBehind = 1024;
		else
			leftBehind = ntext;
		ntext -= leftBehind;
		do {
			charsWritten = send(socketFD, text, leftBehind, 0);
			if (charsWritten <0) error("SERVER: ERROR writing plaintext to socket");
			leftBehind -= charsWritten;
			text += charsWritten;
		} while (leftBehind > 0);
	}
}

/***********************************************************************************************
 * Function: readFromSocket
 * Description: This function reads a string from a socket. If the length of the string is longer
 * 		than 1024, then the string is read in chunks of 1024 chars.
 * Arguments: socketFD: int, the file descriptor of the socket that the string is read from
 * 	      text: char*, a pointer to the memory location that the string will be written to
 * 	      ntext: int, the length of string
 * Precondition: the memory for text is allocated and initialized to '\0'. The length of the string
 * 		 is known.
 * Postcondition: the whole is read from socket and written into text.
 * **********************************************************************************************/
void readFromSocket(int socketFD, char* text, int  ntext)
{	
	int charsRead, leftBehind;
	while (ntext >0)
	{
		if (ntext >= 1024)
			leftBehind = 1024;
		else
			leftBehind = ntext;
		ntext -= leftBehind;
		do{
			charsRead = recv(socketFD, text, leftBehind, 0);
			if (charsRead < 0) error("SERVER: ERROR reading from socket");
			leftBehind -= charsRead;
			text += charsRead;
		} while (leftBehind > 0);
	}
}


/****************************************************************************************************
 * Function: checkAndDecode
 * Description: This server function makes sure that the connected client is otp_dec and decodes the
 * 		message with the key both of which are sent by the client.
 * Arguments: establishedConnectionFD: int, the file descriptor of the connected socket
 * Precondition: the socket is already connected
 * Postcondition: If the client is otp_dec, then this function receives ciphertext and key, then send
 * 		  the plaintext to client. If the client is not otp_dec, then it closes the connection
 * 		  right away.
 * ****************************************************************************************************/
void checkAndDecode(int establishedConnectionFD)
{
	//get the verification message from client
	int charsRead, charsWritten;
	char buffer[64];
	memset(buffer, '\0', sizeof(buffer));
	charsRead = recv(establishedConnectionFD, buffer, 3, 0); //read the client's message from the socket
	if (charsRead < 0) error("ERROR reading from socket");

	//send a verification message back to the client
	charsWritten = send(establishedConnectionFD, "dec", 3, 0);
	if (charsWritten < 0) error("ERROR writing to socket");
	
	//if the client is not otp_dec, then close this connection and exit
	if ( strcmp(buffer, "dec") != 0)
	{
		close(establishedConnectionFD);
		exit(2);
	}

	//receive the length of ciphertext
	memset(buffer, '\0', sizeof(buffer));
	charsRead = recv(establishedConnectionFD, buffer, 10, 0); //read the client's message from the socket
	if (charsRead < 0) error("ERROR reading from socket");
	int nciphertext = atoi(buffer);

	//receive the ciphertext
	char *ciphertext = (char*)calloc(nciphertext, sizeof(char));
	if (!ciphertext) error("ERROR allocating memory in otp_enc_d");
	readFromSocket(establishedConnectionFD, ciphertext, nciphertext);
	//receive the key
	char *key = (char*)calloc(nciphertext, sizeof(char));
	if (!key) error("ERROR allocating memory in otp_enc_d");
	readFromSocket(establishedConnectionFD, key, nciphertext);

	//encode the message
	char *plaintext = (char*)calloc(nciphertext, sizeof(char));
	if (!plaintext) error("ERROR allocating memory in otp_enc_d");
	decode(ciphertext, key, plaintext);
	
	writeToSocket(establishedConnectionFD, plaintext, nciphertext);
	
	//close down
	free(ciphertext);
	free(key);
	free(plaintext);
	close(establishedConnectionFD); //close the existing socket which is connected to the client
}

//signal handling function to catch SIGCHLD
void catchSIGCHLD(int signo)
{
	childFinished = 1;
}

//USAGE: program_name port_number
int main(int argc, char* argv[])
{
	//check the command line usage and arguments
	if (argc < 2) { fprintf(stderr, "USAGE: %s port\n", argv[0]); exit(1); } //check usage & args
	
	//set up the signal handler for SIGCHLD
	struct sigaction SIGCHLD_action = {{0}};
	SIGCHLD_action.sa_handler = catchSIGCHLD;
	sigfillset(&SIGCHLD_action.sa_mask);
	SIGCHLD_action.sa_flags=0;
	sigaction(SIGCHLD, &SIGCHLD_action, NULL);

	int listenSocketFD, establishedConnectionFD, portNumber;// charsRead, charsWritten;
	socklen_t sizeOfClientInfo;
	struct sockaddr_in serverAddress, clientAddress;


	//set up address struct for this server process
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); //clear out the address struct
	portNumber = atoi(argv[1]); //get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // any address is allowed for connection to this process

	//set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // create the socket
	if (listenSocketFD < 0) error("ERROR opening socket");

	//Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) //connect socket to port
		error("ERROR on binding");
	listen(listenSocketFD, 5); //Flip the socket on - it can now receive up to 5 connections
	int nChildren = 0;
	const int MAXCHILDREN = 5;

	//set up sigset_t to Block that will be used to block SIGCHLD
	sigset_t toBlock;	
	if (sigemptyset(&toBlock) == -1) error("Fail to set sigset_t toBlock");
	if (sigaddset(&toBlock, SIGCHLD) == -1) 
		error("Fail to add SIGCHLD to sigset_t toBlock");

	while (1) 
	{
		// if the number of child processes is smaller than MAXCHILDREN, then accept a connection and fork off a child
		if (nChildren < MAXCHILDREN)
		{
			//block SIGCHLD while the parent is accepting a new connection
			if (sigprocmask(SIG_BLOCK, &toBlock, NULL) != 0)
				error("SIGCHLD is not blocked for accept()");
			//Accept a connection, blocking if one is not available until one connects
			sizeOfClientInfo = sizeof(clientAddress); // get the size of the address for the client that will connect
			establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); //accept
			if (establishedConnectionFD <0) error("ERROR on accept");

			//unblock SIGCHLD
			if (sigprocmask(SIG_UNBLOCK, &toBlock, NULL) != 0)
				error("SIGCHLD is not unblocked");

			//fork off a child
			pid_t spawnPid = fork();
			if (spawnPid == -1) error("Hull Breach!");
			else if (spawnPid == 0) //child process
			{
				checkAndDecode(establishedConnectionFD); //establishedConnectionFD is closed in this call
				exit(0);
			}
			else //parent process
			{
				nChildren++;
			}
		
		}
		
		//check whether any of the child processes has finished
		if (childFinished == 1)
		{
			pid_t childPid;
			do
			{
				childPid = waitpid(-1, NULL, WNOHANG);
				if (childPid)
				{
					if (nChildren <=0)
					{
						fprintf(stderr, "ERROR COUNTING CHILDREN\n");
						exit(1);
					}
					nChildren--;
				}

			} while (childPid);

			if (nChildren == 0)
				childFinished = 0;
		}
	}
	
	close(listenSocketFD); //close the listening socket
	return 0;
}
