#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>


unsigned int load_key(const char *filename) {
    FILE *keyFile;
    unsigned int K;
    keyFile = fopen(filename, "r");
    if (keyFile == NULL) {
        fprintf(stderr, "Error: No se pudo abrir el archivo %s\n", filename);
        exit(1);
    }
    if (fscanf(keyFile, "%X", &K) != 1) {
        fprintf(stderr, "Error: No se pudo leer la clave de %s\n", filename);
        fclose(keyFile);
        exit(1);
    }
    fclose(keyFile);
    printf("Clave K de 32 bits cargada: %08X\n", K);
    return K;
}

void load_sbox(const char *filename, unsigned int s_box[16]) {
    FILE *sboxFile;
    sboxFile = fopen(filename, "r");
    if (sboxFile == NULL) {
        fprintf(stderr, "Error: No se pudo abrir el archivo %s\n", filename);
        exit(1);
    }
    for (int i = 0; i < 16; i++) {
        if (fscanf(sboxFile, "%X", &s_box[i]) != 1) {
            fprintf(stderr, "Error: El archivo S-box está incompleto o corrupto.\n");
            fclose(sboxFile);
            exit(1);
        }
    }
    fclose(sboxFile);
    printf("S-box de 16 valores cargada correctamente.\n");
}

void cargar_permutacion(const char *filename, int p[], int tamano) {
    FILE *f = fopen(filename, "r");
    if (f == NULL) {
        fprintf(stderr, "Error: No se pudo abrir el archivo %s para lectura\n", filename);
        exit(1);
    }
    for (int i = 0; i < tamano; i++) {
        if (fscanf(f, "%d", &p[i]) != 1) {
            fprintf(stderr, "Error: El archivo de permutación %s está corrupto o incompleto.\n", filename);
            fclose(f);
            exit(1);
        }
    }
    fclose(f);
    printf("Permutación cargada correctamente desde %s.\n", filename);
}

unsigned char permutar_bits(unsigned char input_byte, int pi[8]) {
    unsigned char output_byte = 0;
    for (int i = 0; i < 8; i++) {
        unsigned char bit = (input_byte >> (7-i)) & 1;
        output_byte |= (bit << (7 - pi[i])); 
    }
    return output_byte;
}

unsigned char encrypt_byte(unsigned char M, unsigned int K, const unsigned int s_box[16], int pi[8]) {
    unsigned char kArray[4];
    kArray[0]= (K >> 24) & 0xFF;
    kArray[1]= (K >> 16) & 0xFF;
    kArray[2]= (K >> 8) & 0xFF;
    kArray[3]= K & 0xFF;
    unsigned char low, high, nhigh, nlow, state;
    state = M;
    for(int i = 0; i < 3; i++){
        state = state ^ kArray[i]; 
        high = state >> 4;
        low = state & (unsigned char)(0x0F);
        nhigh = s_box[(int)high];
        nlow = s_box[(int)low];
        state = (nhigh << 4) | nlow;
        state = permutar_bits(state, pi);
    }
    unsigned char C = state ^ kArray[3];
    return C;
}

char *base64_encode_openssl(const unsigned char *data, size_t input_length) {
    BIO *b64, *bmem;
    BUF_MEM *bptr;
    char *encoded_data = NULL;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); 

    BIO_write(b64, data, (int)input_length);
    BIO_flush(b64);
    
    BIO_get_mem_ptr(b64, &bptr);
    encoded_data = (char *)malloc(bptr->length + 1);
    if (encoded_data) {
        memcpy(encoded_data, bptr->data, bptr->length);
        encoded_data[bptr->length] = '\0';
    }

    BIO_free_all(b64);
    return encoded_data;
}

void guardar_ciphertext_base64(const char *base64_c, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (f == NULL) {
        fprintf(stderr, "Error: No se pudo abrir el archivo %s para escritura.\n");
        return;
    }
    fprintf(f, "%s", base64_c);
    fclose(f);
}

unsigned char *encipher_ctr_mode(const char *plaintext, unsigned int K, const unsigned int s_box[16], int pi[8], size_t *out_len) {
    size_t plain_len = strlen(plaintext);
    *out_len = plain_len + 1;
    
    unsigned char *output_block = (unsigned char *)malloc(*out_len); 
    if (!output_block) {
        fprintf(stderr, "Error de alocación de memoria para el bloque de salida.\n");
        exit(1);
    }
    
    unsigned char iv = (unsigned char)(rand() % 256);
    output_block[0] = iv; // El primer byte del bloque de salida es el IV

    printf("IV/Contador Inicial generado: %02X\n", iv);

    for (size_t i = 0; i < plain_len; i++) {
        unsigned char counter = iv + i; 
        unsigned char keystream_byte = encrypt_byte(counter, K, s_box, pi);

        output_block[i + 1] = plaintext[i] ^ keystream_byte;
    }
    
    return output_block;
}

#include <stdio.h>
#include <stdlib.h>

char *read_plaintext_from_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error al abrir el archivo");
        return NULL;
    }

    // 1. Ir al final del archivo para determinar el tamaño
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 2. Asignar memoria para el contenido (+1 para el terminador nulo '\0')
    char *buffer = (char *)malloc(length + 1);
    if (!buffer) {
        fprintf(stderr, "Error de memoria al cargar el archivo.\n");
        fclose(file);
        return NULL;
    }

    // 3. Leer el contenido del archivo al buffer
    size_t read_size = fread(buffer, 1, length, file);
    buffer[read_size] = '\0'; // Asegurar que termine en nulo

    fclose(file);
    return buffer;
}

int main() {
    char key_filename[100];
    char perm_filename[100]; 
    char sbox_filename[100];
    
    unsigned int K;
    unsigned int s_box[16];
    int pi_cargada[8];
    size_t output_block_len;
    
    srand(time(NULL)); 

    printf("--- Programa de Cifrado (Counter Mode) ---\n");
    printf("Ingresa el nombre del archivo de la clave (ej: key.txt): ");
    scanf("%99s", key_filename);
    printf("Ingresa el nombre del archivo de la S-box (ej: sbox.txt): ");
    scanf("%99s", sbox_filename);
    printf("Ingresa el nombre del archivo de permutación (ej: permutacion.txt): ");
    scanf("%99s", perm_filename);

    K = load_key(key_filename);
    load_sbox(sbox_filename, s_box);
    cargar_permutacion(perm_filename, pi_cargada, 8); 

    char filename[256];
    printf("Ingresa el nombre del archivo (ej. mensaje.txt): ");
    scanf("%255s", filename);

    char *plaintext = read_plaintext_from_file(filename);

    unsigned char *output_block = encipher_ctr_mode(plaintext, K, s_box, pi_cargada, &output_block_len);
    
    char *base64_c = base64_encode_openssl(output_block, output_block_len);
    
    if (base64_c) {
        guardar_ciphertext_base64(base64_c, "ciphertext.txt");

        printf("\n--- Cifrado guardado ---\n");
        free(base64_c);
    } else {
        fprintf(stderr, "Error al codificar Base64.\n");
    }

    free(output_block);

    return 0;
}