/* secuencial.c - Version SECUENCIAL (sin MPI) de la busqueda por fuerza
 * bruta de la llave privada DES. Es la linea base contra la cual se miden
 * los speedups de las versiones paralelas.
 *
 * Lee el texto cifrado desde un archivo, recibe la palabra clave a buscar
 * como parametro y, opcionalmente, el tamano del espacio de busqueda en
 * bits (2^bits llaves). Recorre las llaves 0, 1, 2, ... en orden hasta
 * encontrar una cuyo descifrado contenga la palabra clave.
 *
 * Uso:
 *   ./secuencial <archivo_cifrado> <palabra_clave> [bits]
 */

#include "des.h"
#include "keyutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void uso(const char *prog) {
    fprintf(stderr, "Uso: %s <archivo_cifrado> <palabra_clave> [bits]\n", prog);
    fprintf(stderr, "  bits : espacio de busqueda = 2^bits llaves (1..56, por defecto 56)\n");
}

int main(int argc, char *argv[]) {
    if (argc < 3) { uso(argv[0]); return 1; }

    const char *archivo = argv[1];
    const char *palabra = argv[2];
    int bits = (argc >= 4) ? atoi(argv[3]) : 56;

    if (palabra[0] == '\0') {
        fprintf(stderr, "Error: la palabra clave no puede estar vacia\n");
        return 1;
    }
    if (bits < 1 || bits > 56) {
        fprintf(stderr, "Error: bits debe estar entre 1 y 56\n");
        return 1;
    }

    long len;
    unsigned char *cipher = leer_archivo(archivo, &len);
    if (!cipher) {
        fprintf(stderr, "Error: no se pudo leer el archivo cifrado '%s'\n", archivo);
        return 1;
    }
    if (len % 8 != 0) {
        fprintf(stderr, "Error: el texto cifrado debe ser multiplo de 8 bytes (es %ld)\n", len);
        free(cipher);
        return 1;
    }

    unsigned char *work = malloc((size_t)len + 1);
    if (!work) {
        fprintf(stderr, "Error: memoria insuficiente\n");
        free(cipher);
        return 1;
    }

    uint64_t upper = 1ULL << bits;
    long long encontrada = -1;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t k = 0; k < upper; ++k) {
        if (probar_llave(k, cipher, (int)len, work, palabra)) {
            encontrada = (long long)k;
            break;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double seg = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

    if (encontrada >= 0) {
        memcpy(work, cipher, (size_t)len);
        des_ecb((uint64_t)encontrada, work, (int)len, 1);
        work[len] = 0;
        printf("Llave encontrada : %lld\n", encontrada);
        printf("Archivo cifrado  : %s\n", archivo);
        printf("Palabra clave    : %s\n", palabra);
        printf("Texto descifrado : %s\n", work);
    } else {
        printf("Llave NO encontrada en el espacio [0, 2^%d)\n", bits);
        printf("Archivo cifrado  : %s\n", archivo);
        printf("Palabra clave    : %s\n", palabra);
    }
    printf("Tiempo           : %.4f s\n", seg);

    free(work);
    free(cipher);
    return 0;
}
