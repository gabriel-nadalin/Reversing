#include <stdio.h>
#include <time.h>
#include <stdlib.h>

typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef unsigned long    qword;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    word;
typedef struct eh_frame_hdr eh_frame_hdr, *Peh_frame_hdr;


int main(void){
    int iVar1;
    time_t tVar2;
    long in_FS_OFFSET;
    uint seed;
    uint local_3c;
    long i;
    FILE *arquivoIn;
    size_t size;
    void *pointer;
    FILE *arquivoOut;
    long local_10;

    arquivoIn = fopen("flag.enc","rb");
    fseek(arquivoIn,0,2);
    size = ftell(arquivoIn) - 4;
    fseek(arquivoIn,0,0);
    pointer = malloc(size);
    fread(&seed,4,1,arquivoIn);
    fread(pointer,size,1,arquivoIn);
    fclose(arquivoIn);
    srand(seed);
    for (i = 0; i < (long)size; i = i + 1) {
        iVar1 = rand();
        local_3c = rand();
        local_3c = local_3c & 7;
        *(byte *)((long)pointer + i) =
                *(byte *)((long)pointer + i) >> (byte)local_3c |
                *(byte *)((long)pointer + i) << 8 - (byte)local_3c;
        *(byte *)((long)pointer + i) = *(byte *)((long)pointer + i) ^ (byte)iVar1;
    }
    arquivoOut = fopen("flag.dec","wb");
    fwrite(pointer,1,size,arquivoOut);
    fclose(arquivoOut);
    return 0;
}