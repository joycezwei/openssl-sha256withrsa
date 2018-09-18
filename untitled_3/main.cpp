#include <iostream>
#include "common_tool.h"



int main() {
    common_tool ct;
    std::string message="my sign message";
    std::string prikey="MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCGzWIxRW4gO5V6npTs2X/VuqjVDMntifmSwOTQ68emYZjYnSx85NovrmjtWPhgWzCGu2CV09ihe5nwX2JXWXNbDbxgK3J+5spSEcGmH5SQgiWB2TfdrbXOqGZ6ogZ2zIKju36Cp1oFY8gnUYoSCOpYqb9CoVlqG0A1n9z6Qi4u7s256pZi7fSzTwMrLJgHCI2nbqTw7deQCqRPeulwQNh6n1ftmJStqfztf7XJUc211oRPgun+e7DUQt1Ork3CwYREdjsXsCcbm8KRsb5LNYzNnsA/wtFUb4Fn5F/JtyveU3i4uZcvZQf6r3eUpaEMTbbrj7gx0YMKR6ShnIM9+4+JAgMBAAECggEARwpyFxlKAj6kdiygu3mcPxzR4QWOXVr7ZfW2IMxBOVPx4yZhzaglvD8kGQFsVAt6tWaGbi9o2SF0bRM3lmUTwAarIduDyZEDSuEEtvGpr8aG0bmSEYd8at6gszw0P+Njbbpf36cmb/S4BNCZ/QspxXQf0ZOKtbqKyjfnkxPRlvWLK2JokD+aYSa7VuP83D9MXmn28LP6VALcFYGuiljXMsBcT1hWV3nS8SqzW5+gHNP5EBiSzmQU9wChrRiwqLNVkZq574uTYXQGEBdDkeB6fNL+mzSCia692SZTOO13g2YcfL/8BJ1tI8YnitLxDZ6CJvKswHGnbShK86Pz6SlmKQKBgQC9X8E/0XytzHDuxjXmG+c21C1TGnULlkwnsAcETMdz0LN24uyXkI5VTSQ5jImd5044elQttzxWNsakAyiTrCrQey1C3gASJtkpEXDfZnLNTx6OgN2vHQtcFZMc6nsQm3KpF6j/ZLUtcrRj9m9RdCOkYDjSBlVe5FLU7KZUx66BOwKBgQC2Ooti2kIK0ERg0PLQGVJIxiIaxos3NtsNbGZUneHzuIbMqRgD7yqb/zDVAK1bV5yTnHuEtbndyXT8CxBV4Xz+uxD/JXEHB0t9htrtQ8ER93Smg8wcut9xS/EUJslN4TBrCkx2X5nEbyP7V+1CBqrlmefSvearUxklEL8oPhPmCwKBgB/JyA2nY49lBvv9x6RlwK0idq1Bfq5AP25WDQd6v+w/9zAYrXBPsqS8+zyxy5P29NlkJ2c5H+a08Sks4o3PU6yFULatv0NMxB0xsUm+z7yI8G8pUI0JihOeB4DOF3RVM60QrKyaQhNr8r3o6wy4Oxdnk4Il0ATKvODDDLSkhDVrAoGBAKH2FrydT+VchemmzKi4WLHlp5o0rLc+QiMEHU9Ho/OCJgzwnS+h+jT78uLd3zY4ACoSApZJDhFZZGg/TR2HdBjTGqArHvIoQagnm50Vgxv82+jDaz59uOpxnKtUbcaSRv5cAOmUvo4gWdKiq3TriCjZSXm83q+XA9o1sDCMPBNRAoGAKk8DZjOpjFvN2PNdPNRgexhy7mVsIFtzlt/0CuAJYuqelg1H22cUnnALs1LLZ2qEF5uzyZgChA7z19cGSKsAR2hWg9QXSpxmqZnPSCgm2yc71ok49p+JlZ6DtjKn4az4nF2koyfpSuh1FRYhLT4h8cMXDna385V/RZzhOrYN8ho=";
    std::string signtxt=ct.sign(prikey.c_str(),message);
    std::cout<<signtxt<<std::endl;

    BIO *bufio = NULL;
    RSA *rsa = NULL;
    bufio = BIO_new(BIO_s_file());
    BIO_read_filename(bufio, "rsa_public_key_1.pem");
    rsa = PEM_read_bio_RSA_PUBKEY(bufio, NULL, NULL, NULL);

    std::cout<<ct.verify_rsa(rsa,message,signtxt)<<std::endl;

    return 0;
}