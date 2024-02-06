# Simple Encryptor - Reverse Engineering

## Descrição do problema

O nosso desafio foi escolhido na plataforma HackTheBox e tem como título o nome **Simple Encryptor**.

Ao abrir o site do exercício https://app.hackthebox.com/challenges/simple-encryptor, encontramos a seguinte descrição:

"On our regular checkups of our secret flag storage server we found out that we were hit by ransomware! The original flag data is nowhere to be found, but luckily we not only have the encrypted file but also the encryption program itself."

**Conteúdo do problema**

Além da descrição mostrada acima, temos como base os seguintes arquivos:

- encrypt: <br>
        Esse arquivo é o programa de encriptação usado para gerar o arquivo flag.enc (O encrypt utiliza o arquivo flag que contém a string para ser criptografada e gera o arquivo flag.enc)
    <br><br>
- flag.enc
    <br> Esse arquivo possui o conteúdo encriptografado gerado por meio do arquivo encrypt


## Resolução do problema

### **Transformação do código de encriptação**

Quando pegamos para solucionar o problema descrito nos deparamos com aquele arquivo encrypt e pensamos em como obter o conteúdo dentro dele, para saber mais sobre o programa de encriptação. Para isso ser feito, utilizamos o programa Ghidra para gerar o **arquivo em linguagem c** equivalente ao arquivo **encrypt binário**.

Após a conversão, ficamos com o arquivo ```encrypt.c``` que contém o código em linguagem C.

Aqui abaixo podemos ver uma parte desse arquivo encrypt.c:

```c
undefined8 main(void)

{
  int iVar1;
  time_t tVar2;
  long in_FS_OFFSET;
  uint local_40;
  uint local_3c;
  long local_38;
  FILE *local_30;
  size_t local_28;
  void *local_20;
  FILE *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_30 = fopen("flag","rb");
  fseek(local_30,0,2);
  local_28 = ftell(local_30);
  fseek(local_30,0,0);
  local_20 = malloc(local_28);
  fread(local_20,local_28,1,local_30);
  fclose(local_30);
  tVar2 = time((time_t *)0x0);
  local_40 = (uint)tVar2;
  srand(local_40);
  for (local_38 = 0; local_38 < (long)local_28; local_38 = local_38 + 1) {
    iVar1 = rand();
    *(byte *)((long)local_20 + local_38) = *(byte *)((long)local_20 + local_38) ^ (byte)iVar1;
    local_3c = rand();
    local_3c = local_3c & 7;
    *(byte *)((long)local_20 + local_38) =
         *(byte *)((long)local_20 + local_38) << (sbyte)local_3c |
         *(byte *)((long)local_20 + local_38) >> 8 - (sbyte)local_3c;
  }
  local_18 = fopen("flag.enc","wb");
  fwrite(&local_40,1,4,local_18);
  fwrite(local_20,1,local_28,local_18);
  fclose(local_18);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return 0;
}
```

É fácil de notar que os nomes das variáveis estão todos com indicação numérica e de difícil identificação de acordo com suas funcionalidades.

Para resolver esse impasse, vamos reescrever essas variáveis com nomes mais legíveis para facilitar o processo de entendimento (Geramos então o código do arquivo encryptModified.c):

```c
undefined8 main(void)
{
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
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  arquivoIn = fopen("flag","rb");
  fseek(arquivoIn,0,2);
  size = ftell(arquivoIn);
  fseek(arquivoIn,0,0);
  pointer = malloc(size);
  fread(pointer,size,1,arquivoIn);
  fclose(arquivoIn);
  tVar2 = time((time_t *)0x0);
  seed = (uint)tVar2;
  srand(seed);
  for (i = 0; i < (long)size; i = i + 1) {
    iVar1 = rand();
    *(byte *)((long)pointer + i) = *(byte *)((long)pointer + i) ^ (byte)iVar1;
    local_3c = rand();
    local_3c = local_3c & 7;
    *(byte *)((long)pointer + i) =
         *(byte *)((long)pointer + i) << (sbyte)local_3c |
         *(byte *)((long)pointer + i) >> 8 - (sbyte)local_3c;
  }
  arquivoOut = fopen("flag.enc","wb");
  fwrite(&seed,1,4,arquivoOut);
  fwrite(pointer,1,size,arquivoOut);
  fclose(arquivoOut);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return 0;
}
```

Agora sim, reescrevendo o nome das variáveis para representar suas funções, conseguiremos avançar com mais facilidade pelo programa.

### **Entendendo a parte da encriptação**

Depois de muito tempo analisando o código, a parte realmente mais útil para nós está na parte da main, vamos observar o que ela faz:

```c
undefined8 main(void)
{
  // Variáveis usadas para acesso ao arquivo, manipulação de offset, seed para números aleatórios e entre outros
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
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  
  // Abrindo arquivo para leitura em binário
  arquivoIn = fopen("flag","rb");
  // O 2 representa SEEK_END e faz o ponteiro ir para o fim do arquivo
  fseek(arquivoIn,0,2);
  // Pega o tamanho do arquivo com base na última posição válida do arquivo e na primeira posição válida do arquivo
  size = ftell(arquivoIn);
  fseek(arquivoIn,0,0);
  pointer = malloc(size);
  // Copia para o pointer, todo o conteúdo do arquivo
  fread(pointer,size,1,arquivoIn);
  fclose(arquivoIn);
  // Cria variável que representa o tempo atual
  tVar2 = time((time_t *)0x0);
  // Cria seed e usa para gerar números alatórios
  seed = (uint)tVar2;
  srand(seed);
  // Para cada caractere do arquivo, vamos executar um algoritmo
  for (i = 0; i < (long)size; i = i + 1) {
    // Gera número aleatório
    iVar1 = rand();
    // Realiza XOR bit a bit entre o caractere do arquivo e a variável aleatória e coloca naquela posição do pointer
    *(byte *)((long)pointer + i) = *(byte *)((long)pointer + i) ^ (byte)iVar1;
    // Gera variável aleatória que estará entre 0 e 7
    // Isso é possível pois quando fazemos um AND com 7, estamos considerando apenas os 3 primeiros bits do número aleatório, que faz o mesmo estar dentro do range de 0 até 7
    local_3c = rand();
    local_3c = local_3c & 7;
    // Dado o conteúdo do arquivo, que está representado pelo conteúdo apontado pelo ponteiro, vamos dividí-lo com base na variável aleatória local_3c
    // Em seguida, iremos pegar a primeira parte (caracteres da posição 0 até posição local_3c - 1) e inverter com a segunda parte (caracteres da posição local_3c até size-1)
    *(byte *)((long)pointer + i) =
         *(byte *)((long)pointer + i) << (sbyte)local_3c |
         *(byte *)((long)pointer + i) >> 8 - (sbyte)local_3c;
  }
  // Abre arquivo para escrita em binário
  arquivoOut = fopen("flag.enc","wb");
  // Escreve a seed usada, como os primeiros 4 bytes do arquivo (!!!!MUITO IMPORTANTE ISSO!!!!)
  fwrite(&seed,1,4,arquivoOut);
  // Escreve a flag criptografada no restante do arquivo
  fwrite(pointer,1,size,arquivoOut);
  fclose(arquivoOut);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
  // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return 0;
}
```

Como mostrado no código, a parte fundamental do problema é a linha ```fwrite(&seed,1,4,arquivoOut);``` <br><br>
Através dela conseguiremos saber, dado um arquivo criptografado, qual foi a seed usada para gerar os caracteres e consequentemente, dá para transformá-los no conteúdo original, antes da encriptação. 

### Criando código para desencriptação

Agora que sabemos que a seed usada para encriptação dos dados está contida nos primeiros 4 bytes do arquivo gerado, podemos pegá-la para criar o nosso próprio algoritmo de desencriptação. Faremos isso no arquivo decrypt.c.

O conteúdo do programa que criamos está mostrado abaixo e faz o inverso do arquivo de encryptação para conseguirmos o conteúdo original e consequentemente a flag:

```c
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
```