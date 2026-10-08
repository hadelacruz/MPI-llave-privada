/* cifrar.c - Utilidad para cifrar o descifrar un archivo de texto con DES
 * usando una llave privada arbitraria pasada como parametro.
 *
 * Cubre el requisito de la Parte B: "cifre un texto cargado desde un archivo
 * (.txt) usando una llave privada arbitraria (como parametro)". Tambien se
 * usa para generar los archivos cifrados que luego rompen los programas de
 * fuerza bruta.
 *
 * Uso:
 *   ./cifrar -e <archivo_entrada> <llave> <archivo_salida>   (cifrar)
 *   ./cifrar -d <archivo_entrada> <llave> <archivo_salida>   (descifrar)
 */

#include "des.h"
#include "keyutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void uso(const char *prog) {
    fprintf(stderr, "Uso: %s <-e|-d> <archivo_entrada> <llave> <archivo_salida>\n", prog);
    fprintf(stderr, "  -e : cifrar    -d : descifrar\n");
    fprintf(stderr, "  <llave> : entero sin signo en base 10 (ej. 42)\n");
}

int main(int argc, char *argv[]) {
    if (argc != 5) { uso(argv[0]); return 1; }

    int cifrar;
    if (strcmp(argv[1], "-e") == 0)      cifrar = 1;
    else if (strcmp(argv[1], "-d") == 0) cifrar = 0;
    else { uso(argv[0]); return 1; }

    const char *entrada = argv[2];

    char *fin;
    unsigned long long llave = strtoull(argv[3], &fin, 10);
    if (argv[3][0] == '\0' || *fin != '\0') {
        fprintf(stderr, "Llave invalida: '%s'\n", argv[3]);
        return 1;
    }
    const char *salida = argv[4];

    long len;
    unsigned char *datos = leer_archivo(entrada, &len);
    if (!datos) {
        fprintf(stderr, "Error: no se pudo leer el archivo de entrada '%s'\n", entrada);
        return 1;
    }

    /* DES opera en bloques de 8 bytes; se rellena con ceros hasta el
     * siguiente multiplo de 8 (relleno nulo, invisible al imprimir). */
    int padded = (int)(((len + 7) / 8) * 8);
    unsigned char *buf = calloc((size_t)padded, 1);
    if (!buf) {
        fprintf(stderr, "Error: memoria insuficiente\n");
        free(datos);
        return 1;
    }
    memcpy(buf, datos, (size_t)len);
    free(datos);

    des_ecb((uint64_t)llave, buf, padded, cifrar ? 0 : 1);

    FILE *f = fopen(salida, "wb");
    if (!f) {
        fprintf(stderr, "Error: no se pudo crear el archivo de salida '%s'\n", salida);
        free(buf);
        return 1;
    }
    fwrite(buf, 1, (size_t)padded, f);
    fclose(f);

    if (cifrar)
        printf("Cifrado:  '%s' (%ld bytes -> %d) con llave %llu  =>  '%s'\n",
               entrada, len, padded, llave, salida);
    else
        printf("Descifrado: '%s' con llave %llu  =>  '%s'\n", entrada, llave, salida);

    free(buf);
    return 0;
}
