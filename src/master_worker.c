/* master_worker.c - ALTERNATIVA 2 al enfoque naive: MAESTRO-TRABAJADOR con
 * asignacion DINAMICA de trabajo (self-scheduling).
 *
 * El proceso 0 es el MAESTRO: no busca, solo reparte "trozos" (chunks) del
 * espacio de llaves por demanda. Los procesos 1..N-1 son TRABAJADORES: cada
 * uno pide un trozo, lo recorre, y si no encuentra la llave pide otro.
 *
 * Motivacion (ver informe): a diferencia del reparto estatico (naive o
 * ciclico), aqui ningun proceso se queda "atascado" con un bloque enorme
 * mientras otros ya terminaron. El trabajo se balancea solo, lo que da un
 * tiempo esperado consistente (~ espacio / (N-1)) y es robusto ante nodos
 * de distinta velocidad. El costo es que un proceso se dedica a coordinar.
 *
 * Protocolo de mensajes:
 *   worker -> master : TAG_REQ   (pide un trozo)
 *   worker -> master : TAG_FOUND (encontro la llave K; luego se detiene)
 *   master -> worker : TAG_REP   (inicio del trozo, o -1 = detente)
 *
 * Uso:
 *   mpirun -np <N> ./master_worker <archivo_cifrado> <palabra_clave> [bits]
 *   (requiere N >= 2)
 */

#include "des.h"
#include "keyutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>

#define TAG_REQ   1
#define TAG_FOUND 2
#define TAG_REP   3
#define CHUNK (1u<<15)   /* tamano del trozo de llaves por asignacion */

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    int N, id;
    MPI_Comm comm = MPI_COMM_WORLD;
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    if (N < 2) {
        if (id == 0) fprintf(stderr, "Error: master_worker requiere al menos 2 procesos (-np >= 2)\n");
        MPI_Finalize();
        return 1;
    }
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

    uint64_t upper = 1ULL << bits;

    MPI_Barrier(comm);
    double t0 = MPI_Wtime();
    long long found = -1;

    if (id == 0) {
        /* ---------------- MAESTRO ---------------- */
        uint64_t next = 0;
        int activos = N - 1;              /* trabajadores aun en marcha */
        while (activos > 0) {
            long long msg;
            MPI_Status st;
            MPI_Recv(&msg, 1, MPI_LONG_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &st);
            if (st.MPI_TAG == TAG_FOUND) {
                found = msg;              /* ese trabajador ya se detuvo */
                activos--;
            } else { /* TAG_REQ */
                long long rep;
                if (found >= 0 || next >= upper) {
                    rep = -1;             /* detente */
                    activos--;
                } else {
                    rep = (long long)next;
                    next += CHUNK;
                }
                MPI_Send(&rep, 1, MPI_LONG_LONG, st.MPI_SOURCE, TAG_REP, comm);
            }
        }
    } else {
        /* ---------------- TRABAJADOR ---------------- */
        unsigned char *work = malloc((size_t)len + 1);
        if (!work) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }
        long long peticion = -1;
        int parar = 0;
        while (!parar) {
            MPI_Send(&peticion, 1, MPI_LONG_LONG, 0, TAG_REQ, comm);
            long long inicio;
            MPI_Recv(&inicio, 1, MPI_LONG_LONG, 0, TAG_REP, comm, MPI_STATUS_IGNORE);
            if (inicio < 0) break;        /* el maestro ordena detenerse */

            uint64_t fin = (uint64_t)inicio + CHUNK;
            if (fin > upper) fin = upper;
            for (uint64_t k = (uint64_t)inicio; k < fin; ++k) {
                if (probar_llave(k, cipher, (int)len, work, palabra)) {
                    long long f = (long long)k;
                    MPI_Send(&f, 1, MPI_LONG_LONG, 0, TAG_FOUND, comm);
                    parar = 1;
                    break;
                }
            }
        }
        free(work);
    }

    double t1 = MPI_Wtime();
    MPI_Bcast(&found, 1, MPI_LONG_LONG, 0, comm);   /* todos conocen el resultado */
    double elapsed = t1 - t0, max_elapsed;
    MPI_Reduce(&elapsed, &max_elapsed, 1, MPI_DOUBLE, MPI_MAX, 0, comm);

    if (id == 0) {
        unsigned char *work = malloc((size_t)len + 1);
        if (!work) { fprintf(stderr, "memoria insuficiente\n"); MPI_Abort(comm, 1); }
        if (found >= 0) {
            memcpy(work, cipher, (size_t)len);
            des_ecb((uint64_t)found, work, (int)len, 1);
            work[len] = 0;
            printf("Llave encontrada : %lld\n", found);
            printf("Archivo cifrado  : %s\n", archivo);
            printf("Palabra clave    : %s\n", palabra);
            printf("Texto descifrado : %s\n", work);
        } else {
            printf("Llave NO encontrada en [0, 2^%d)\n", bits);
            printf("Archivo cifrado  : %s\n", archivo);
            printf("Palabra clave    : %s\n", palabra);
        }
        printf("Enfoque          : maestro-trabajador (dinamico)\n");
        printf("Procesos         : %d (1 maestro + %d trabajadores)\n", N, N - 1);
        printf("Tiempo           : %.4f s\n", max_elapsed);
        free(work);
    }

    free(cipher);
    MPI_Finalize();
    return 0;
}
