#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <assert.h>

char * decrypt(char *filename, char *key) {
    gcry_cipher_hd_t handle;
    gcry_error_t err = 0;

    FILE *f = fopen(filename, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f) - 16;
    // first 16 bytes are the IV
    fseek(f, 16, SEEK_SET);  /* same as rewind(f); */

    char *string = malloc(fsize + 1);
    fread(string, fsize, 1, f);

    string[fsize] = 0;
    char iv[17];
    rewind(f);
    fread(iv, 16, 1, f);
    iv[16] = 0;
    fclose(f);
    gcry_check_version (NULL);
    gcry_control( GCRYCTL_DISABLE_SECMEM_WARN );
    //gcry_control( GCRYCTL_INIT_SECMEM, 16384, 0 );
       err = gcry_cipher_open (&handle, GCRY_CIPHER_TWOFISH128,GCRY_CIPHER_MODE_CFB,0);

       if (err)
         {
           fprintf (stderr, "Failure: &#37;s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
         }
	err = gcry_cipher_setkey (handle, key ,16);
	if (err)
         {
           fprintf (stderr, "Key Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
         }
    err = gcry_cipher_setiv(handle, iv, 16);
	if (err)
         {
           fprintf (stderr, "IV Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
         }
    char *foo;
    foo = malloc(fsize+1);
    err = gcry_cipher_decrypt(handle, foo, fsize, string, fsize);
    if (err) {
        fprintf(stderr, "Decrypt failure%s/%s\n",
                gcry_strsource(err),
                gcry_strerror(err));
        }
  gcry_cipher_close(handle);
return foo;
}
