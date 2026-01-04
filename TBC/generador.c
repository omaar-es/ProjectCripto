#include <stdio.h>
#include <stdlib.h>
#include <time.h> 

void generar_permutation(int pi[], int tamano) {
    for (int i = 0; i < tamano; i++) {
        pi[i] = i;
    }
    for (int i = 0; i < tamano; i++) {
        int j = rand() % tamano; 
        int aux = pi[i];
        
        pi[i] = pi[j];
        pi[j] = aux;
    }
}

int *generate_permutation_inverse(int *pi, int tamano) {
    int *pi_inv = malloc(tamano * sizeof(int));
    if (!pi_inv) {
        fprintf(stderr, "Error de alocación de memoria para pi_inv\n");
        exit(1);
    }

    for (int i = 0; i < tamano; i++) {
        pi_inv[pi[i]] = i;
    }
    return pi_inv;
}

void guardar_permutacion(const char *filename, const int p[], int tamano) {
    FILE *f = fopen(filename, "w");
    if (f == NULL) {
        fprintf(stderr, "Error: No se pudo abrir el archivo %s para escritura\n", filename);
        exit(1);
    }
    
    for (int i = 0; i < tamano; i++) {
        fprintf(f, "%d\n", p[i]);
    }
    
    fclose(f);
    printf("Permutacion guardada\n");
}

void generar_y_guardar_clave(const char *filename) {
    FILE *keyFile;
    unsigned int K = (rand() & 0xFF) << 24 | (rand() & 0xFF) << 16 | (rand() & 0xFF) << 8 | (rand() & 0xFF);

    keyFile = fopen(filename, "w");
    if (keyFile == NULL) {
        fprintf(stderr, "Error: No se pudo abrir el archivo %s para escritura\n", filename);
        exit(1);
    }
    
    fprintf(keyFile, "%X\n", K); 
    
    fclose(keyFile);
    printf("Clave K generada \n", filename, K);
}

void generar_y_guardar_sboxes(const char *sbox_filename, const char *sbox_inv_filename, unsigned int s_box[16]) {
    FILE *sboxFile, *sboxInvFile;
    unsigned int s_box_inv[16];

    generar_permutation((int*)s_box, 16);
    
    for (int i = 0; i < 16; i++) {
        s_box_inv[s_box[i]] = i;
    }

    sboxFile = fopen(sbox_filename, "w");
    if (sboxFile == NULL) {
        fprintf(stderr, "Error: No se pudo abrir el archivo %s para escritura\n", sbox_filename);
        exit(1);
    }
    for (int i = 0; i < 16; i++) {
        fprintf(sboxFile, "%X\n", s_box[i]);
    }
    fclose(sboxFile);
    printf("S-box generada y guardada en: %s\n", sbox_filename);

    sboxInvFile = fopen(sbox_inv_filename, "w");
    if (sboxInvFile == NULL) {
        fprintf(stderr, "Error: No se pudo abrir el archivo %s para escritura\n", sbox_inv_filename);
        exit(1);
    }
    for (int i = 0; i < 16; i++) {
        fprintf(sboxInvFile, "%X\n", s_box_inv[i]);
    }
    fclose(sboxInvFile);
    printf("S-box inversagenerada \n");
}

int main() {
    unsigned int s_box[16];
    int pi[8];
    int *pi_inv;
    
    srand(time(NULL)); 

    printf("--- Generador de Componentes de Cifrado ---\n");
    
    generar_y_guardar_clave("key.txt");
    
    generar_y_guardar_sboxes("sbox.txt", "sbox_inv.txt", s_box);

    generar_permutation(pi, 8);
    pi_inv = generate_permutation_inverse(pi, 8);
    
    guardar_permutacion("permutacion.txt", pi, 8);
    guardar_permutacion("permutacion_inversa.txt", pi_inv, 8);
    
    free(pi_inv);

    printf("\n Listo \n");
    return 0;
}