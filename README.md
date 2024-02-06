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

Quando pegamos para solucionar o problema descrito nos deparamos com aquele arquivo encrypt e pensamos em como obter o conteúdo dentro dele, para saber mais sobre o programa de encriptação. Para isso ser feito, utilizamos o programa Ghidra para gerar o **arquivo em linguagem c** equivalente ao arquivo **encrypt binário**.

Após a conversão, ficamos com o seguinte código:

```c


```




