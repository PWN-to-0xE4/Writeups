#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

unsigned char * parse_input(const char *);
void decrypt(FILE *, const unsigned char *, const char *);
bool check_predicate(const char *);
bool mutate_key(char *);

int main (void) {
	/* get the input */
	unsigned char * input = parse_input("../out.txt");

	/* open the output file */
	FILE * fp = fopen("output", "w");

	/* perform bruteforce */
	char key[] = "aaaaaaa";
	do {
		decrypt(fp, input, key);
	} while (mutate_key(key));

	/* close resources */
	fclose(fp);
	free(input);
	exit(EXIT_SUCCESS);
}

unsigned char * parse_input(const char * fin) {
	/* open the input file */
	FILE * fp = fopen(fin, "r");

	/* parse the input */
	unsigned char * input = calloc(63L, sizeof(unsigned char));
	for (int i = 0; i < 63; i++) {
		switch (i) {
			case 0:
				fscanf(fp, "[%hhu, ", &input[i]);
				break;
			case 62:
				fscanf(fp, "%hhu]", &input[i]);
				break;
			default:
				fscanf(fp, "%hhu, ", &input[i]);
				break;
		}
	}

	/* Close the file */
	fclose(fp);

	return input;
}

/*
 * Perform a decryption with the given key
 */
void decrypt(FILE * fp, const unsigned char * input, const char * key) {
	/* Copy in the input as we are going to modify it */
	unsigned char enc[64];
	memcpy(enc, input, 63);

	for (int i = 0; i < 63; i++) {
		/* perform the decryption step */
		enc[i] ^= key[i % 3] ^ key[i / 3 % 7] ^ key[i / 21];
	}

	if (check_predicate((char *) enc)) {
		fprintf(fp, "%s -> %s\n", key, enc);
		fprintf(stderr, "%s -> %s\n", key, enc);
	}
}

/* check the assertions on the decrypted output */
bool check_predicate(const char * dec) {
	/* count("}") == 1 */
	char * first_bracket = strchr(dec, '}');
	if (first_bracket == NULL || strchr(first_bracket + 1, '}') != NULL) {
		return false;
	}

	/* count("tjctf{") == 1 */
	char * tjctf = strstr(dec, "tjctf{");
	if (tjctf == NULL || strstr(tjctf + 1, "tjctf{") != NULL) {
		return false;
	}
	
	/* count(" ") == 5 */
	char * space = strchr(dec, ' ');
	for (int i = 0; i < 5; i++) {
		if (space == NULL) {
			return false;
		}
		space = strchr(space + 1, ' ');
	}
	if (space != NULL) {
		return false;
	}

	return true;
}

/* transform the key to the next one */
bool mutate_key(char * key) {
	for (int i = 0; i < 7; i++) {
		if (key[i]++ == 'z') {
			key[i] = 'a';
		} else {
			return true;
		}
	}
	return false;
}
