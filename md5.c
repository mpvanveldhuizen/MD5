//Matt Van Veldhuizen
//2/24/15
//md5.c
//Calculate the MD5 hash on a given input

#include <string.h>
#include <stdio.h>

//Rotate to the left by some amount
int ROTL(unsigned int x, unsigned int n) {
	return (((x) << (n)) | ((x) >> (32 - (n))));
}

void md5_process(unsigned int *count, unsigned int *abcd, unsigned char *buf, const unsigned char *data) {
	//Initialize hash value for this chuck
	unsigned int a = abcd[0];
	unsigned int b = abcd[1];
	unsigned int c = abcd[2];
	unsigned int d = abcd[3];
	unsigned int xbuf[16];
	const unsigned int *X;

	//Round constants based off the following
	//for(int i = 0; i < 64; i++)
	//	arr[i] = floor(abs(sin(i + 1)) * (pow(2,32));

	//Round One Constants table
	unsigned int roneArr[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
				  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
				  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
				  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821};

	//Round Two Constants table
	unsigned int rtwoArr[] = {0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
				  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
				  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
				  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a};

	//Round Three Constants table
	unsigned int rthreeArr[] = {0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
				    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
				    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
				    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665};

	//Round Four Constants table
	unsigned int rfourArr[] = {0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
				   0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
				   0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
				   0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

	//Breaking chucks into 16 32-bit words
	if (!((data - (const unsigned char *)0) & 3)) {
		//data are properly aligned
		X = (const unsigned int *)data;
	}
	else {
		//not aligned
		memcpy(xbuf, data, 64);
		X = xbuf;
	}

	//Round 1
	//Shift amounts for round 1: 7, 12, 17, 22
	//	a = b + ((a + F(B, C, D) + X[k] + roneArr[i]) << s)
	//	F(B, C, D) = (((B) & (C)) | (~(B) & (D)))
	int i;
	for(i = 0; i < 16; i += 4) {
		a = ROTL((a + (((b) & (c)) | (~(b) & (d))) + X[i] + roneArr[i]), 7) + b;
		d = ROTL((d + (((a) & (b)) | (~(a) & (c))) + X[i+1] + roneArr[i+1]), 12) + a;
		c = ROTL((c + (((d) & (a)) | (~(d) & (b))) + X[i+2] + roneArr[i+2]), 17) + d;
		b = ROTL((b + (((c) & (d)) | (~(c) & (a))) + X[i+3] + roneArr[i+3]), 22) + c;
	}

	//Round 2
	//Shuft amounts for round 2: 5, 9, 14, 20
	//	a = b + ((a + G(B, C, D) + X[k] + rtowArr[i]) << s)
	//	G(B, C, D) = (((B) & (D)) | ((C) & ~(D)))
	for(i = 0; i < 16; i+=4){
		int z = i+1;
		if(z > 15)
			z -= 16;
		a = ROTL((a + (((b) & (d)) | ((c) & ~(d))) + X[z] + rtwoArr[i]), 5) + b;

		int f = i+6;
		if(f > 15)
			f -= 16;
		d = ROTL((d + (((a) & (c)) | ((b) & ~(c))) + X[f] + rtwoArr[i+1]), 9) + a;

		int r = i+11;
		if(r > 15)
			r -= 16;
		c = ROTL((c + (((d) & (b)) | ((a) & ~(b))) + X[r] + rtwoArr[i+2]), 14) + d;

		int g = i+16;
		if(g > 15)
			g -= 16;
		b = ROTL((b + (((c) & (a)) | ((d) & ~(a))) + X[g] + rtwoArr[i+3]), 20) + c;
	}

	//Round 3
	//Shift amounts for round 3: 4, 11, 16, 23
	//	a = b + ((a + H(B, C, D) + X[k] + rthreeArr[i])) << s)
	//	H(B, C, D) = ((B) ^ (C) ^ (D))
	for(i = 15; i >= 0; i-=4){
		int z = i-10;
		if(z < 0)
			z += 16;
		a = ROTL((a + ((b) ^ (c) ^ (d)) + X[z] + rthreeArr[15-i]), 4) + b;

		int f = i-7;
		if(f < 0)
			f += 16;
		d = ROTL((d + ((a) ^ (b) ^ (c)) + X[f] + rthreeArr[16-i]), 11) + a;

		int r = i-4;
		if(r < 0)
			r += 16;
		c = ROTL((c + ((d) ^ (a) ^ (b)) + X[r] + rthreeArr[17-i]), 16) + d;

		int g = i-1;
		if(g < 0)
			g += 16;
		b = ROTL((b + ((c) ^ (d) ^ (a)) + X[g] + rthreeArr[18-i]), 23) + c;
	}

	//Round 4
	//Shift amounts for round 4: 6, 10, 15, 21
	//	a = b + ((a + I(B, C, D) + X[k] + rfourArr[i]) << s)
	//	I(B, C, D) = ((C) ^ ((B) | ~(D)))
	for(i = 15; i >= 0; i-=4){
		int z = i-15;
		if(z < 0)
			z += 16;
		a = ROTL((a + ((c) ^ ((b) | ~(d))) + X[z] + rfourArr[15-i]), 6) + b;

		int f = i-8;
		if(f < 0)
			f += 16;
		d = ROTL((d + ((b) ^ ((a) | ~(c))) + X[f] + rfourArr[16-i]), 10) + a;

		int r = i-1;
		if(r < 0)
			r += 16;
		c = ROTL((c + ((a) ^ ((d) | ~(b))) + X[r] + rfourArr[17-i]), 15) + d;

		int g = i-10;
		if(g < 0)
			g += 16;
		b = ROTL((b + ((d) ^ ((c) | ~(a))) + X[g] + rfourArr[18-i]), 21) + c;
	}

	//Add this cunck's hash to the result
	abcd[0] += a;
	abcd[1] += b;
	abcd[2] += c;
	abcd[3] += d;
}

void md5_append(unsigned int *count, unsigned int *abcd, unsigned char *buf, unsigned char *data, int nbytes) {
	const unsigned char *p = data;
	int left = nbytes;
	int offset = (count[0] >> 3) & 63;
	unsigned int nbits = (unsigned int)(nbytes << 3);

	//if message length is 0 do nothing
	if (nbytes <= 0)
		return;

	//Update the message length
	count[1] += nbytes >> 29;
	count[0] += nbits;
	if (count[0] < nbits)
		count[1]++;

	//Process an initial partial block
	if (offset) {
		int copy = (offset + nbytes > 64 ? 64 - offset : nbytes);

		memcpy(buf + offset, p, copy);
		if (offset + copy < 64)
			return;
		p += copy;
		left -= copy;
		md5_process(count, abcd, buf, buf);
	}

	//Process full blocks
	for (; left >= 64; p += 64, left -= 64)
		md5_process(count, abcd, buf, p);

	//Process a final partial block
	if (left)
		memcpy(buf, p, left);
}

void md5_finish(unsigned int *count, unsigned int *abcd, unsigned char *buf, unsigned char digest[16]) {
	//Padding to fit to 512 block
	unsigned char pad[64] = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	unsigned char data[8];

	//Save the length before padding
	int i;
	for (i = 0; i < 8; ++i)
		data[i] = (unsigned char)(count[i >> 2] >> ((i & 3) << 3));
	//Pad to 56 bytes mod 64
	md5_append(count, abcd, buf, pad, ((55 - (count[0] >> 3)) & 63) + 1);
	//Append the length
	md5_append(count, abcd, buf, data, 8);
	for (i = 0; i < 16; ++i)
		digest[i] = (unsigned char)(abcd[i >> 2] >> ((i & 3) << 3));
}

int main() {
	//message length in bits
	unsigned int count[2];
	//digest buffer
	unsigned int abcd[4];
	//accumulate block
	unsigned char buf[64];
	//message to hash
	char message[256];
	//result of md5 hash
	unsigned char digest[16];
	//Initialize message lenght and digest buffer
	count[0] = 0;
	count[1] = 0;
	abcd[0] = 0x67452301;	//A
	abcd[1] = 0xefcdab89;	//B
	abcd[2] = 0x98badcfe;	//C
	abcd[3] = 0x10325476;	//D

	printf("Enter String to Hash:\n");
	scanf("%[^\n]s", message);

	md5_append(count, abcd, buf, (unsigned char *)message, strlen(message));
	md5_finish(count, abcd, buf, digest);

	printf("MD5 (%s) = ", message);
	int i;
	for(i = 0; i < 16; i++)
		printf("%02x", digest[i]);
	printf("\n");

	return 0;
}