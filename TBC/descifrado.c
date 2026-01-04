#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/bio.h>
#include <openssl/evp.h>


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
}

char *cargar_base64_desde_archivo(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (f == NULL) {
        fprintf(stderr, "Error: No se pudo abrir el archivo %s para lectura.\n", filename);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *raw_data = malloc(fsize + 1);
    if (!raw_data) {
        fprintf(stderr, "Error de alocación de memoria para Base64.\n");
        fclose(f);
        exit(1);
    }
    fread(raw_data, 1, fsize, f);
    fclose(f);
    raw_data[fsize] = 0;

    char *clean_data = (char *)malloc(fsize + 1);
    if (!clean_data) {
        fprintf(stderr, "Error de alocación de memoria para Base64 limpia.\n");
        free(raw_data);
        exit(1);
    }
    size_t j = 0;
    for (size_t i = 0; i < fsize; i++) {
        char c = raw_data[i];
        if (isalnum(c) || c == '+' || c == '/' || c == '=') {
            clean_data[j++] = c;
        }
    }
    clean_data[j] = '\0';
    free(raw_data);
    
    return clean_data;
}

unsigned char permutar_bits(unsigned char input_byte, int pi[8]) {
    unsigned char output_byte = 0;
    for (int i = 0; i < 8; i++) {
        unsigned char bit = (input_byte >> (7-i)) & 1;
        output_byte |= (bit << (7 - pi[i])); 
    }
    return output_byte;
}


unsigned char *base64_decode_openssl(const char *encoded_data, size_t *output_length) {
    BIO *b64, *bmem;
    int len = (int)strlen(encoded_data);
    unsigned char *buffer = NULL;
    int decoded_len;

    *output_length = (len * 3) / 4; 
    buffer = (unsigned char *)malloc(*output_length + 1);
    if (!buffer) return NULL;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf((void*)encoded_data, len);
    b64 = BIO_push(b64, bmem);
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    decoded_len = BIO_read(b64, buffer, len);
    
    if (decoded_len < 0) {
        free(buffer);
        buffer = NULL;
        *output_length = 0;
    } else {
        *output_length = (size_t)decoded_len;
        buffer[decoded_len] = '\0'; 
    }

    BIO_free_all(b64);
    return buffer;
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

char *decipher_ciphertext_ctr_mode(const unsigned char *ciphertext, size_t len, unsigned int K, const unsigned int s_box[16], int pi[8]) {
    len=len-1;
    char *plaintext = (char *)malloc(len+1); 
    if (!plaintext) {
        fprintf(stderr, "Error de alocación de memoria para plaintext\n");
        exit(1);
    }
    
    unsigned char iv= ciphertext[0];
    printf("IV recuperado para descifrado: %02X\n", iv);
    for (size_t i = 0; i < len; i++) {
        unsigned char counter = iv + i; 
        unsigned char keystream_byte = encrypt_byte(counter, K, s_box, pi);
        plaintext[i] = ciphertext[i+1] ^ keystream_byte;
    }
    plaintext[len] = '\0';
    return plaintext;
}

void save_plaintext_to_file(const char *filename, const char *plaintext) {
    // Abrimos el archivo en modo "w" (write). 
    // Si el archivo ya existe, se sobrescribirá.
    FILE *file = fopen(filename, "w");
    
    if (file == NULL) {
        perror("Error al crear el archivo de salida");
        return;
    }

    // Escribimos el contenido del string en el archivo
    fprintf(file, "%s", plaintext);

    // Cerramos el flujo
    fclose(file);
    
    printf("El mensaje ha sido guardado exitosamente en: %s\n", filename);
}

int main() {
    char key_filename[100];
    char perm_filename[100]; 
    char sbox_inv_filename[100];
    char base64_file_filename[100];
    char *base64_ciphertext = NULL;
    
    unsigned int K;
    unsigned int s_box[16];
    int pi_normal_cargada[8];
    int *pi_inv_calculada = NULL;
    size_t ciphertext_len;

    printf("--- Programa de Descifrado (Bloque 2) ---\n");
    printf("Ingresa el nombre del archivo de la clave: ");
    scanf("%99s", key_filename);
    printf("Ingresa el nombre del archivo de la S-box inversa: ");
    scanf("%99s", sbox_inv_filename);
    printf("Ingresa el nombre del archivo de la permutacion: ");
    scanf("%99s", perm_filename);
    printf("Ingresa el nombre del archivo que contiene el texto cifrado Base64: ");
    scanf("%99s", base64_file_filename);

    K = load_key(key_filename);
    load_sbox(sbox_inv_filename, s_box); 
    cargar_permutacion(perm_filename, pi_normal_cargada, 8); 

    pi_inv_calculada = generate_permutation_inverse(pi_normal_cargada, 8);

    base64_ciphertext = cargar_base64_desde_archivo(base64_file_filename);

    unsigned char *ciphertext_bytes = base64_decode_openssl(base64_ciphertext, &ciphertext_len);
    
    if (ciphertext_bytes == NULL) {
        fprintf(stderr, "Error: La decodificación Base64 falló (OpenSSL).\n");
        free(base64_ciphertext);
        free(pi_inv_calculada);
        return 1;
    }
    
    char *plaintext = decipher_ciphertext_ctr_mode(ciphertext_bytes, ciphertext_len, K, s_box, pi_normal_cargada);
    
    printf("\n--- Resultado del descifrado guardado ---\n");
    const char *nombre_archivo_salida = "mensaje_descifrado.txt";
    save_plaintext_to_file(nombre_archivo_salida, plaintext);

    free(base64_ciphertext);
    free(ciphertext_bytes);
    free(plaintext);
    free(pi_inv_calculada);

    return 0;
}