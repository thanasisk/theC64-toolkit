lib :
	gcc -fPIC --shared -o decryptor.so -lgcrypt decryptor.c
clean :
	rm decryptor.so
dataclean:
	rm *.tar.gz installer

