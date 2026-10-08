/* bruteforce.c - Version PARALELA "NAIVE" (de bloques) de la busqueda por
 * fuerza bruta de la llave DES, con MPI. Es la version base entregada en
 * Canvas, adaptada para:
 *   (1) usar el modulo DES propio des.c/des.h en vez de <rpc/des_crypt.h>;
 *   (2) leer el texto cifrado desde un archivo y la palabra clave como
 *       parametro (programacion defensiva de entradas);
 *   (3) corregir dos fallos del codigo original:
 *       - "off-by-one": el ultimo valor de cada bloque nunca se probaba;
 *       - los procesos no se detenian al encontrar otro la llave (el
 *         MPI_Irecv nunca progresaba). Aqui se sondea con MPI_Iprobe.
 *
 * Reparto NAIVE: el espacio [0, 2^bits) se divide en N bloques CONTIGUOS,
 * uno por proceso. El proceso id busca en [id*base, (id+1)*base).
 *
 * Uso:
 *   mpirun -np <N> ./bruteforce <archivo_cifrado> <palabra_clave> [bits]
 */

#include "des.h"
#include "keyutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>

#define TAG_STOP 1              /* mensaje: "ya se encontro la llave K"     */
#define CHECK_INTERVAL (1u<<12) /* cada cuantas iteraciones se sondea STOP  */

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    int N, id;
    MPI_Comm comm = MPI_COMM_WORLD;
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    if (argc < 3) {
        if (id == 0)
            fprintf(stderr, "Uso: mpirun -np <N> %s <archivo_cifrado> <palabra_clave> [bits]\n", argv[0]);
        MPI_Finalize();
        return 1;
    }
    const char *archivo = argv[1];
    const char *palabra = argv[2];
    int bits = (argc >= 4) ? atoi(argv[3]) : 56;
    if (bits < 1 || bits > 56) {
        if (id == 0) fprintf(stderr, "Error: bits debe estar entre 1 y 56\n");
        MPI_Finalize();
        return 1;
    }

    /* --- El proceso 0 lee el archivo y lo difunde (MPI_Bcast) --- */
    long len = 0;
    unsigned char *cipher = NULL;
    if (id == 0) {
        cipher = leer_archivo(archivo, &len);
        if (!cipher || len % 8 != 0 || palabra[0] == '\0') {
            fprintf(stderr, "Error: archivo cifrado invalido o palabra clave vacia\n");
            len = -1;
        }
    }
    MPI_Bcast(&len, 1, MPI_LONG, 0, comm);
    if (len < 0) { free(cipher); MPI_Finalize(); return 1; }

    if (id != 0) cipher = malloc((size_t)len + 1);
    if (!cipher) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }
    MPI_Bcast(cipher, (int)len, MPI_UNSIGNED_CHAR, 0, comm);
    cipher[len] = 0;

    unsigned char *work = malloc((size_t)len + 1);
    if (!work) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }

    /* --- Reparto naive de bloques contiguos --- */
    uint64_t upper = 1ULL << bits;
    uint64_t base  = upper / (uint64_t)N;
    uint64_t mylower = base * (uint64_t)id;
    uint64_t myupper = (id == N - 1) ? upper : base * (uint64_t)(id + 1); /* rango [mylower, myupper) */

    long long found = -1;

    MPI_Barrier(comm);
    double t0 = MPI_Wtime();

    unsigned long contador = 0;
    for (uint64_t k = mylower; k < myupper; ++k) {
        if (probar_llave(k, cipher, (int)len, work, palabra)) {
            found = (long long)k;
            for (int j = 0; j < N; ++j)
                if (j != id)
                    MPI_Send(&found, 1, MPI_LONG_LONG, j, TAG_STOP, comm);
            break;
        }
        if ((++contador % CHECK_INTERVAL) == 0) {
            int flag = 0;
            MPI_Status st;
            MPI_Iprobe(MPI_ANY_SOURCE, TAG_STOP, comm, &flag, &st);
            if (flag) {
                MPI_Recv(&found, 1, MPI_LONG_LONG, st.MPI_SOURCE, TAG_STOP, comm, MPI_STATUS_IGNORE);
                break;
            }
        }
    }

    double t1 = MPI_Wtime();

    /* Correccion: todos conocen el resultado con una reduccion (MAX).
     * found vale -1 en los procesos que no encontraron ni recibieron STOP. */
    long long global_found;
    MPI_Allreduce(&found, &global_found, 1, MPI_LONG_LONG, MPI_MAX, comm);

    double elapsed = t1 - t0, max_elapsed;
    MPI_Reduce(&elapsed, &max_elapsed, 1, MPI_DOUBLE, MPI_MAX, 0, comm);

    if (id == 0) {
        if (global_found >= 0) {
            memcpy(work, cipher, (size_t)len);
            des_ecb((uint64_t)global_found, work, (int)len, 1);
            work[len] = 0;
            printf("Llave encontrada : %lld\n", global_found);
            printf("Archivo cifrado  : %s\n", archivo);
            printf("Palabra clave    : %s\n", palabra);
            printf("Texto descifrado : %s\n", work);
        } else {
            printf("Llave NO encontrada en [0, 2^%d)\n", bits);
            printf("Archivo cifrado  : %s\n", archivo);
            printf("Palabra clave    : %s\n", palabra);
        }
        printf("Enfoque          : naive (bloques contiguos)\n");
        printf("Procesos         : %d\n", N);
        printf("Tiempo           : %.4f s\n", max_elapsed);
    }

    /* Drenar cualquier mensaje STOP que haya quedado sin recibir. */
    int flag = 1;
    while (flag) {
        MPI_Status st;
        MPI_Iprobe(MPI_ANY_SOURCE, TAG_STOP, comm, &flag, &st);
        if (flag) {
            long long tmp;
            MPI_Recv(&tmp, 1, MPI_LONG_LONG, st.MPI_SOURCE, TAG_STOP, comm, MPI_STATUS_IGNORE);
        }
    }

    free(work);
    free(cipher);
    MPI_Finalize();
    return 0;
}
