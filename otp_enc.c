/**************************************************************************************
 * Author: Xiaoqiong Dong
 * Date: Nov 29, 2018
 * Description: This program takes in the plaintext and key, sends them to the server
 * 		to encript the plaintext, and then outputs the ciphertext to stdout.
 *************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>

//reporting error
void error(const char* msg)
{
	perror(msg);
	exit(1);
}

//check validity of the input
//If the text or key has any character other than A-Z and space, return 0
//If the length of the text is longer than key, return 0
//Return 1 otherwise
//-1: key length < text length
//-2: plaintext has invalid character
//-3: key has invalid character
int checkTexts(const char* text, const char* key)
{
	int lenText = strlen(text);
	int lenKey = strlen(key);
	if (lenText > lenKey)
		return -1;
	
	//check whether text has any invalid character
	int i;
	for (i=0; i<lenText; i++)
	{
		if ((text[i] < 'A' && text[i] != ' ') || text[i] > 'Z')
			return -2;
	}

	//check whether key has any invalid character
	for (i=0; i<lenKey; i++)
	{
		if ((key[i] < 'A' && key[i] != ' ') || key[i] > 'Z')
			return -3;
	}
	
	// valid inputs
	return 1;
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
			if (charsWritten <0) error("CLIENT: ERROR writing plaintext to socket");
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
			if (charsRead < 0) error("CLIENT: ERROR reading from socket");
			leftBehind -= charsRead;
			text += charsRead;
		} while (leftBehind > 0);
	}
}

//USAGE: programName plaintextFile keyFile portNo
int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;

	if (argc < 4) { fprintf(stderr, "USAGE: %s hostname port\n", argv[0]); exit(1); } //check usage & args

	/*open the files, read in plaintext and key, and check for validity*/
	//open the files
	FILE *fplaintext, *fkey;
	if ( !(fplaintext = fopen(argv[1], "r")))
		error("Fail to open the plaintext file");
	if ( !(fkey = fopen(argv[2], "r")))
		error("Fail to open the key file");
	//read in plaintext and key
	char *plaintext = NULL, *key = NULL;
	size_t len = 0;
	ssize_t nplaintext, nkey;
	if ((nplaintext = getline(&plaintext, &len, fplaintext))== -1)
		error("Fail to read plaintext");
	plaintext[strcspn(plaintext, "\n")] = '\0';

	len = 0;
	if ((nkey = getline(&key, &len, fkey))== -1)
		error("Fail to read key");
	key[strcspn(key, "\n")] = '\0';
	//close the files
	fclose(fplaintext);
	fclose(fkey);
	//check for validity
	int valid;
	if ((valid =checkTexts(plaintext, key)) < 0) //exit on invalid input
	{
		switch (valid)
		{
			case -1: fprintf(stderr, "key \"%s\" is too short\n", argv[2]);
				 break;
			case -2: fprintf(stderr, "plaintext \"%s\" has invalid characters\n", argv[1]);
				 break;
			default: fprintf(stderr, "key \"%s\" has invalid characters\n", argv[2]);
				 break;
		}
		exit(1);
	}

	
	char* ciphertext; 
	if (!(ciphertext = (char*)calloc(nplaintext, sizeof(char)))) //exit if fail to allocate memory
		error("Fail to allocate memory for ciphertext");
	

	//set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); //clear out the address struct
	portNumber = atoi(argv[3]); //get the port number, conver to an integer from a string
	serverAddress.sin_family = AF_INET; //create a network-capable socket
	serverAddress.sin_port = htons(portNumber); //store the port number
	serverHostInfo = gethostbyname("localhost"); //convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); //copy in address

	//set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); //create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket");

	//connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) //connect socket to address
		error("CLIENT: ERROR connecting");
	//send verification message to server
	char encVerify[4];
	memset(encVerify, '\0', sizeof(encVerify));
	strcpy(encVerify, "enc");
	charsWritten = send(socketFD, encVerify, 3, 0);
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	
	//receive verification message from server
	char buffer[1024];
	memset(buffer, '\0', 1024);
	charsRead = recv(socketFD, buffer, 3, 0);
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");
	if (strcmp(encVerify, buffer) != 0)  // If the server is not otp_enc_d, exit
	{
		if (strcmp(buffer, "dec") == 0)
			fprintf(stderr, "ERROR: Could not contact otp_dec_d on port %d\n", portNumber);
		else
			fprintf(stderr, "ERROR: Could not contact port %d\n", portNumber);
		exit(2);
	}
	// send the length of the plaintext, then send over the plaintext
	char textLength[10];
	memset(textLength, '\0', sizeof(textLength));
	sprintf(textLength,"%d",(int)nplaintext);
	charsWritten = send(socketFD, textLength, 10, 0);
	if (charsWritten < 0) error ("CLIENT: ERROR writing textLength to socket");	
	writeToSocket(socketFD, plaintext, nplaintext);

	// send the key to the socket
	writeToSocket(socketFD, key, nplaintext);
	
	//receive ciphertext from server
	readFromSocket(socketFD, ciphertext, nplaintext);	
	printf("%s\n", ciphertext);
	fflush(stdout);

	//close down	
	free(plaintext);
	free(key);
	free(ciphertext);

	close(socketFD); 

	return 0;
}
