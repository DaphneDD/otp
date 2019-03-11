/**************************************************************************************
 * Author: Xiaoqiong Dong
 * Date: Nov 24, 2018
 * Description: This program creates a newline ended string of randomaly generated 
 * 		characters of A-Z and space. The number of random characters are passed
 * 		in commandline. The string is outputted to stdout.
 *************************************************************************************/

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

/**************************************************************************************
 * Function: error
 * Description: prints out error to stderr, and exit with 1
 * Argument: msg, const char*, customized error message
 * Return: N/A
 * Precondition: N/A
 * Postcondition: msg and error are printed to stderr, and program exits with 1
 * ***********************************************************************************/
void error (const char* msg)
{
	perror(msg);
	exit(1);
}

int main(int argc, char* argv[])
{
	//checking the commandline
	if (argc < 2)
	{
		fprintf(stderr, "USAGE: %s length\n", argv[0]);
		exit(1);
	}

	int n = atoi(argv[1]);
	//seed the random generator
	srand(time(0));
	
	//print out randomaly generated characters one by one
	int i, c;
	char key;
	for (i=0; i<n; i++)
	{
		c = rand() % 27; //27 valid characters: A-Z and space
		if (c >= 0 && c <= 25)   // A-Z
			key = (char)(c + 65);
		else	// space
			key = ' ';
		if (write(STDOUT_FILENO, &key, 1) < 0)
			error("ERROR writing to stdout");
	}

	//write a new line character at the end
	key = '\n';
	if (write(STDOUT_FILENO, &key, 1) < 0)
		error("ERROR writing to stdout");
	return 0;
}

