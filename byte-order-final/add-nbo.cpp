#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>

uint32_t file_read(char* file){
	FILE *fp;
	char read_data[4]={0x00,};
	fp = fopen(file,"rb");
	if(fp == NULL){
		fprintf(stderr,"Error: Could not open file %s - %s\n",file,strerror(errno));
		return -1;
	}
	size_t bytes_read = fread(read_data,1,4,fp);
	fclose(fp);
	if(bytes_read<4){
		fprintf(stderr,"Error: File %s is smaller than 4 bytes\n",file);
		return -1;
	}
	uint32_t* p =reinterpret_cast<uint32_t*> (read_data);
	uint32_t n = htonl(*p);
	
	return n;

}
int main(char argc, char* argv[]){
	if(argc<3){
		printf("Usage: fileio.exe <File_Name1.bin> <File_Name2.bin>");
		return 0;
	}

	uint32_t first_n, second_n;
	first_n = file_read(argv[1]);
	second_n = file_read(argv[2]);
	
	if (first_n == -1 || second_n == -1) {
        	return 0;
	}
	printf("%d(0x%x)+%d(0x%x)=%d(0x%x)",(int)first_n,first_n,(int)second_n,second_n,(int)first_n+second_n,first_n+second_n);
	return 0;
}
