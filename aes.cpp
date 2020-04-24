#include <iostream>
#include <string>
#include <stdio.h>
#include <bitset>
#include <math.h>
#include <vector>

using namespace std;

typedef bitset<8> byte;
typedef bitset<32> word;

const int Nr = 10;          // Number of rounds in AES
const int Nk = 4;           // Number of 32 bit words in the key
const int Nb = 4;           // Number of columns (32 bit words) in the state
const int BlockLength = 16; // Nlock length in bytes: AES is 128b


// ecb and cbc implementation and attack

word Rcon[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};  

// Rijndael S-Box used in the SubsByte Step
byte S_Box[16][16] = {  
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},  
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},  
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},  
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},  
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},  
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},  
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},  
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},  
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},  
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},  
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},  
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},  
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},  
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},  
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},  
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}  
};  

// Inverse S-Box. Simply the S-box run in reverse
byte Inv_S_Box[16][16] = {  
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},  
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},  
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},  
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},  
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},  
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},  
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},  
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},  
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},  
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},  
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},  
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},  
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},  
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},  
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},  
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}  
};  


//////////////////////////////////////////////////////////////
//////////////////// Helper Functions ////////////////////////
//////////////////////////////////////////////////////////////

word XOR_Word(word a, word b){
    return a ^ b;
}

byte XOR_Byte(byte a, byte b){
    return a ^ b;
}

// used in CBC mode
void XOR_Blocks(byte state[], int curr_block, int prev_block){
    for (int i = 0; i < BlockLength; ++i){
        state[curr_block] = state[curr_block] ^ state[prev_block];
    }
}

// Rotate or left shift by one byte
// [0, 0, 0, 1] - > [0, 0, 1, 0]
word Rotate_Word(word input){
    word high = input << 8;
    word low = input >> 24;
    return high | low;
}

// Substitution from S-Box. First four bits is row and last four bits is col
word Substitute_Word(word input){
    word new_word;
    for (int i = 0; i < 32; i += 8){
        int row = (input[i + 7] * 8) + (input[i + 6] * 4) + (input[i + 5] * 2) + (input[i + 4]);
        int col =  (input[i + 3] * 8) + (input[i + 2] * 4) + (input[i + 1] * 2) + (input[i]);
        byte val = S_Box[row][col];

        for (int j = 0; j < 8; ++j){
            new_word[i + j] = val[j];
        }
    }
    return new_word;
}

// Multiplication over Galois Fields
byte Mult_Bytes(byte a, byte b){
    byte high_bit;
    byte one_twenty_eight = byte(128);
    byte twenty_seven = byte(27);
    byte one = byte(1);
    byte result = 0;
    for (int i = 0; i < 8; ++i){
        if ((b & one) != 0){
            result = XOR_Byte(result, a);
        }

        high_bit = (byte)(a & one_twenty_eight);
        a = a << 1;

        if (high_bit != 0){
            a = XOR_Byte(a, twenty_seven);
        }
        b = b >> 1;
    }
    return result;
}

// Given initial key, creates key for other rounds and stores them in w[]
void Key_Expansion(byte key[], word key_array[]){

    
    // Need to copy intitial key into the extended key array
    for (int i = 0; i < Nk; ++i){
        // combine every four bytes into one word
        word combination = word(0x00000000);
        word temp;
        temp = key[4 * i].to_ulong();
        temp <<= 24;
        combination |= temp;

        temp = key[4 * i + 1].to_ulong();
        temp <<= 16;
        combination |= temp;

        temp = key[4 * i + 2].to_ulong();
        temp <<= 8;
        combination |= temp;

        temp = key[4 * i + 3].to_ulong();
        combination |= temp;
        key_array[i] = combination;
        cout << key_array[i] << endl;
    }
    
    word prev;
    // cout << "Testing Key Extension Array" << endl;
    for (int i = Nk; i < 4 * (Nr + 1); ++i){
        prev = key_array[i - 1];
        if (i % Nk == 0){
            key_array[i] = key_array[i - Nk] ^ Substitute_Word(Rotate_Word(prev)) ^ Rcon[i / Nk - 1];
        }
        else {
            // key_array[i] = key_array[i - Nk] ^ prev;
            key_array[i] = key_array[i - Nk] ^ prev;
        }
        // cout << key_array[i] << endl;
    }
}

//////////////////////////////////////////////////////////////
//////////////////// Encryption Functions ////////////////////
//////////////////////////////////////////////////////////////


// Four keys from the extended key are XORed with four columns of the state
void Add_Round_Key(byte state[4 * 4], word key_array[4 * (Nr + 1)]){
    for (int i = 0; i < 4; ++i){
        word one = key_array[i] >> 24;
        word two = (key_array[i] << 8) >> 24;
        word three = (key_array[i] << 16) >> 24;
        word four = (key_array[i] << 24) >> 24;

        state[i] = state[i] ^ byte(one.to_ulong());
        state[i + 4] = state[i + 4] ^ byte(two.to_ulong());
        state[i + 8] = state[i + 8] ^ byte(three.to_ulong());
        state[i + 12] = state[i + 12] ^ byte(four.to_ulong());


    }
}

// Given a 4 x 4 byte state (state), divide the bits to find the corresponding value in S_Box
void Substitute_Bytes(byte state[]){
    // Find index for row and column
    for (int i = 0; i < 16; ++i){
        // First four bits is the row number as hexadecimal
        int row = (state[i][7] * 8) + (state[i][6] * 4) + (state[i][5] * 2) + (state[i][4]);
        // Last four bits is the column number as hexadecimal
        int col = (state[i][3] * 8) + (state[i][2] * 4) + (state[i][1] * 2) + (state[i][0]);
        state[i] = S_Box[row][col];
    }
}

// Given state (4 x 4 matrix), rearrange the rows
void Shift_Rows(byte state[]){
    // First row remains unchanged

    // Second row shifts one bit to left
    byte temp = state[4]; // need to keep track of first value 
    for (int i = 0; i < 3; ++i){
        state[i + 4] = state[i + 5];
    }
    // Overwrite last value to first value
    state[7] = temp;

    // Third row shifts two bits to the left
    for (int i = 0; i < 2; ++i){
        temp = state[i + 8]; // keep track of previous value
        state[i + 8] = state[i + 10];
        state[i + 10] = temp; // swap
    }

    // Fourth row shifts three bits to the left
    temp = state[15]; // keep track of first value
    for (int i = 3; i > 0; --i){
        state[i + 12] = state[i + 11];
    }
    state[12] = temp;
}

// Given state (4 x 4 matrix) transform column by column
void Mix_Columns(byte state[]){
    byte s[4], temp[4];
    byte two = byte(0x02), three = byte(0x03);
    for (int i = 0; i < Nb; ++i){
        for (int j = 0; j < 4; ++j){
            s[j] = state[i + (j * 4)];
        }

        temp[0] = Mult_Bytes(two, s[0]) ^ Mult_Bytes(three, s[1]) ^ s[2] ^ s[3];
        temp[1] = s[0] ^ Mult_Bytes(two, s[1]) ^ Mult_Bytes(three, s[2]) ^ s[3];
        temp[2] = s[0] ^ s[1] ^ Mult_Bytes(two, s[2]) ^ Mult_Bytes(three, s[3]);
        temp[3] = Mult_Bytes(three, s[0]) ^ s[1] ^ s[2] ^ Mult_Bytes(two, s[3]);

        for (int j = 0; j < 4; ++j){
            state[i + (j * 4)] = temp[j];
        }
    }
    
}


//////////////////////////////////////////////////////////////
//////////////////// Decryption Functions ////////////////////
//////////////////////////////////////////////////////////////

void Inv_Substitute_Bytes(byte state[]){
    // Find index for row and column
    for (int i = 0; i < 16; ++i){
        // First four bits is the row number as hexadecimal
        int row = (state[i][7] * 8) + (state[i][6] * 4) + (state[i][5] * 2) + (state[i][4]);
        // Last four bits is the column number as hexadecimal
        int col = (state[i][3] * 8) + (state[i][2] * 4) + (state[i][1] * 2) + (state[i][0]);
        state[i] = Inv_S_Box[row][col];
    }
}

// Reversing what we did in Shift_Rows function
void Inv_Shift_Rows(byte state[]){
    // First row remains unchanged

    // Second row shifts one bit to right
    byte temp = state[7]; // need to keep track of first value 
    for (int i = 3; i > 0; --i){
        state[i + 4] = state[i + 3];
    }
    // Overwrite last value to first value
    state[4] = temp;

    // Third row shifts two bits to the right
    for (int i = 0; i < 2; ++i){
        temp = state[i + 8]; // keep track of previous value
        state[i + 8] = state[i + 10];
        state[i + 10] = temp; // swap
    }

    // Fourth row shifts three bits to the right
    temp = state[12]; // keep track of first value
    for (int i = 0; i < 3; ++i){
        state[i + 12] = state[i + 13];
    }
    state[15] = temp;
}

void Inv_Mix_Columns(byte state[]){
    byte s[4], temp[4];
    byte nine = byte(0x09), eleven = byte(0x0b), thirteen = byte(0x0d), fourteen = byte(0x0e);
    for (int i = 0; i < Nb; ++i){
        for (int j = 0; j < 4; ++j){
            s[j] = state[i + (j * 4)];
        }

        temp[0] = Mult_Bytes(fourteen, s[0]) ^ Mult_Bytes(eleven, s[1]) ^ Mult_Bytes(thirteen, s[2]) ^ Mult_Bytes(nine, s[3]);
        temp[1] = Mult_Bytes(nine, s[0]) ^ Mult_Bytes(fourteen, s[1]) ^ Mult_Bytes(eleven, s[2]) ^ Mult_Bytes(thirteen, s[3]);
        temp[2] = Mult_Bytes(thirteen, s[0]) ^ Mult_Bytes(nine, s[1]) ^ Mult_Bytes(fourteen, s[2]) ^ Mult_Bytes(eleven, s[3]);
        temp[3] = Mult_Bytes(eleven, s[0]) ^ Mult_Bytes(thirteen, s[1]) ^ Mult_Bytes(nine, s[2]) ^ Mult_Bytes(fourteen, s[3]);

        for (int j = 0; j < 4; ++j){
            state[i + (j * 4)] = temp[j];
        }
    }
}



void encrypt(byte state[], word input[], int cbc, byte iv[]){
    word key[4];

    if (cbc == 1){
        for (int i = 0; i < 2; ++i){
            state[i] = XOR_Byte(state[i], iv[i]);
        }
    }
    // Round 1 
    for (int i = 0; i < 4; ++i){
        key[i] = input[i];
    }
    Add_Round_Key(state, key);

    // Rounds 2 - 9
    for (int i = 1; i < Nr; ++i){
        if (cbc == 1){
            XOR_Blocks(state, i * 16, i - 1 * 16);
        }
        Substitute_Bytes(state);
        Shift_Rows(state);
        Mix_Columns(state);
        for (int j = 0; j < 4; ++j){
            key[j] = input[4 * i + j];
        }
        Add_Round_Key(state, key);
    }

    // Round 10
    Substitute_Bytes(state);
    Shift_Rows(state);
    for(int i = 0; i < 4; ++i){
        key[i] = input[4 * Nr + i];
    }
    Add_Round_Key(state, key);
}

void decrypt(byte state[], word input[], int cbc, byte iv[]){
    word key[4];
    // Round 1
    for (int i = 0; i < 4; ++i){
        key[i] = input[4 * Nr + i];
    }
    Add_Round_Key(state, key);
    
    cout << "Testing first round in decrypt" << endl;
    for(int i=0; i<16; ++i)  
    {  
        cout << hex << state[i].to_ulong() << " ";  
        if((i+1)%4 == 0)  
            cout << endl;  
    }  
    cout << endl; 

    if (cbc == 1){
        for (int i = 0; i < 2; ++i){
            state[i] = XOR_Byte(state[i], iv[i]);
        }
    }

    // Round 2 - 9
    for (int i = Nr - 1; i > 0; --i){
        Inv_Shift_Rows(state);
        cout << "Testing inv Shift_Rows in decrypt" << endl;
        for(int i=0; i<16; ++i)  
        {  
            cout << hex << state[i].to_ulong() << " ";  
            if((i+1)%4 == 0)  
                cout << endl;  
        }  
        cout << endl; 
        Inv_Substitute_Bytes(state);
        
        cout << "Testing inv Substitute_Bytes in decrypt" << endl;
        for(int i=0; i<16; ++i)  
        {  
            cout << hex << state[i].to_ulong() << " ";  
            if((i+1)%4 == 0)  
                cout << endl;  
        }  
        cout << endl; 
        
        for (int j = 0; j < 4; ++j){
            key[j] = input[4 * i + j];
        }
        Add_Round_Key(state, key);
        
        cout << "Testing add round key in decrypt" << endl;
        for(int i=0; i<16; ++i)  
        {  
            cout << hex << state[i].to_ulong() << " ";  
            if((i+1)%4 == 0)  
                cout << endl;  
        }  
        cout << endl; 
        
        Inv_Mix_Columns(state);
        
        cout << "Testing inv mix columns in decrypt" << endl;
        for(int i=0; i<16; ++i)  
        {  
            cout << hex << state[i].to_ulong() << " ";  
            if((i+1)%4 == 0)  
                cout << endl;  
        }  
        cout << endl; 

        if (cbc == 1){
            XOR_Blocks(state, i * 16, i - 1 * 16);
        }

    }
    
    cout << "Testing mid round in decrypt" << endl;
    for(int i=0; i<16; ++i)  
    {  
        cout << hex << state[i].to_ulong() << " ";  
        if((i+1)%4 == 0)  
            cout << endl;  
    }  
    cout << endl; 

    // Round 10
    Inv_Shift_Rows(state);
    Inv_Substitute_Bytes(state);
    for(int i = 0; i < 4; ++i){
        key[i] = input[i];
    }
    Add_Round_Key(state, key);
}

//////////////////////////////////////////////////////////////
////////////////// AES Encryption Schemes ////////////////////
//////////////////////////////////////////////////////////////

int Find_Padding_Length(int in_length){
    int length_with_pad = (in_length / BlockLength);
    if (length_with_pad % BlockLength != 0){
        ++length_with_pad;
    }
    length_with_pad = length_with_pad * BlockLength;
    return length_with_pad;
}

void Insert_Padding(byte plain_text[], int in_length, int length_with_pad){
    while (in_length < length_with_pad){
        plain_text[in_length] = byte(0x00);
        ++in_length;
    }
    
}


void AES_Encrypt_ECB(byte plain_text[], int in_length, word key_array[]){
    // get padding length of input plain text
    int length_with_pad = Find_Padding_Length(in_length);

    // insert pads if needed to the plain text
    Insert_Padding(plain_text, in_length, length_with_pad);

    byte iv[1]; //placeholder
    // call the encrypt
    encrypt(plain_text, key_array, 0, iv);
}

void AES_Decrypt_ECB(byte cipher_text[], int in_length, word key_array[]){

    // call the decrypt function
    byte iv[1]; // placeholder
    decrypt(cipher_text, key_array, 0, iv);
}

void AES_Encrypt_CBC(byte plain_text[], int in_length, word key_array[], byte iv[]){
    // get padding length of input plain text
    int length_with_pad = Find_Padding_Length(in_length);
    // insert pads if needed to the plain text
    Insert_Padding(plain_text, in_length, length_with_pad);
    // call the encrypt
    encrypt(plain_text, key_array, 1, iv);
}

void AES_Decrypt_CBC(byte cipher_text[], int in_length, word key_array[], byte iv[]){
    // call the decrypt function
    decrypt(cipher_text, key_array, 1, iv);
}

//////////////////////////////////////////////////////////////
///////////////////////// Testing ////////////////////////////
//////////////////////////////////////////////////////////////



void output_matrix(byte matrix[], string msg){
    cout << msg << endl;
    for (int i = 0; i < 16; ++i){
        cout << hex << matrix[i].to_ulong() << " ";
    }
    cout << endl;
}

void Test_Basic(){
    cout << "Testing Basic AES" << endl;
    byte key[16] = {0xA8, 0x33, 0xBA, 0x7E,   
                    0x1D, 0x56, 0xA0, 0x1A,   
                    0x08, 0x51, 0x00, 0x52,   
                    0x5B, 0xF7, 0x3F, 0x41};  
  
    byte plain_text[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    
    // Output the key
    string msg = "Given key is";
    output_matrix(key, msg);

    word key_array[4 * (Nr + 1)];
    Key_Expansion(key, key_array);

    msg = "Plaintext:";
    output_matrix(plain_text, msg);

    encrypt(plain_text, key_array, 0, key);
    msg = "Encrypt";
    output_matrix(plain_text, msg);

    decrypt(plain_text, key_array, 0, key);
    msg = "Decrypt";
    output_matrix(plain_text, msg);
    
}

void Test_Basic_ECB(){
    cout << "Testing Basic ECB" << endl;
    byte key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
  
    byte plain_text[16] = {0xB0, 0x25, 0x26, 0xB9,   
                    0xD5, 0xEB, 0xD9, 0x41,  
                    0x12, 0xC7, 0xED, 0x98,  
                    0x76, 0x85, 0x31, 0xA4}; 
    
    // Output the key
    string msg = "Given key is";
    output_matrix(key, msg);

    word key_array[4 * (Nr + 1)];
    Key_Expansion(key, key_array);

    msg = "Plaintext:";
    output_matrix(plain_text, msg);

    AES_Encrypt_ECB(plain_text, 16, key_array);
    msg = "Encrypt";
    output_matrix(plain_text, msg);

    AES_Decrypt_ECB(plain_text, 16, key_array);
    msg = "Decrypt";
    output_matrix(plain_text, msg);
    
}

void Test_Basic_CBC(){
    cout << "Testing CBC" << endl;
    byte key[16] = {0xA8, 0x33, 0xBA, 0x7E,   
                    0x1D, 0x56, 0xA0, 0x1A,   
                    0x08, 0x51, 0x00, 0x52,   
                    0x5B, 0xF7, 0x3F, 0x41};  
  
    byte plain_text[16] = {0xB0, 0x25, 0x26, 0xB9,   
                    0xD5, 0xEB, 0xD9, 0x41,  
                    0x12, 0xC7, 0xED, 0x98,  
                    0x76, 0x85, 0x31, 0xA4}; 

    byte iv[16] = {0x10, 0x23, 0xB6, 0xB2,   
                    0xC5, 0xEC, 0x69, 0xB1,  
                    0x16, 0xA7, 0xAD, 0x92,  
                    0x56, 0xB5, 0x61, 0xA7}; 
    
    // Output the key
    string msg = "Given key is";
    output_matrix(key, msg);

    word key_array[4 * (Nr + 1)];
    Key_Expansion(key, key_array);

    msg = "Plaintext:";
    output_matrix(plain_text, msg);

    AES_Encrypt_CBC(plain_text, 16, key_array, iv);
    msg = "Encrypt";
    output_matrix(plain_text, msg);

    AES_Decrypt_CBC(plain_text, 16, key_array, iv);
    msg = "Decrypt";
    output_matrix(plain_text, msg);
    
}

void Test_ECB_Without_One_Block(){
    cout << "Testing ECB with missing block" << endl;
    byte plain_text[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  
    byte key[16] = {0xB0, 0x25, 0x26, 0xB9,   
                    0xD5, 0xEB, 0xD9, 0x41,  
                    0x12, 0xC7, 0xED, 0x98,  
                    0x76, 0x85, 0x31, 0xA4}; 

    
    // Output the key
    string msg = "Given key is";
    output_matrix(key, msg);

    word key_array[4 * (Nr + 1)];
    Key_Expansion(key, key_array);

    msg = "Plaintext:";
    output_matrix(plain_text, msg);

    AES_Encrypt_ECB(plain_text, 16, key_array);
    msg = "Encrypt";
    output_matrix(plain_text, msg);

    AES_Decrypt_ECB(plain_text, 16, key_array);
    msg = "Decrypt";
    output_matrix(plain_text, msg);
}

void Test_CBC_Without_One_Block(){
    cout << "Testing CBC with missing block" << endl;
    byte plain_text[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  
    byte key[16] = {0xB0, 0x25, 0x26, 0xB9,   
                    0xD5, 0xEB, 0xD9, 0x41,  
                    0x12, 0xC7, 0xED, 0x98,  
                    0x76, 0x85, 0x31, 0xA4}; 
    
    byte iv[16] = {0x10, 0x23, 0xB6, 0xB2,   
                    0xC5, 0xEC, 0x69, 0xB1,  
                    0x16, 0xA7, 0xAD, 0x92,  
                    0x56, 0xB5, 0x61, 0xA7}; 

    
    // Output the key
    string msg = "Given key is";
    output_matrix(key, msg);

    word key_array[4 * (Nr + 1)];
    Key_Expansion(key, key_array);

    msg = "Plaintext:";
    output_matrix(plain_text, msg);

    AES_Encrypt_CBC(plain_text, 16, key_array, iv);
    msg = "Encrypt";
    output_matrix(plain_text, msg);

    AES_Decrypt_CBC(plain_text, 16, key_array, iv);
    msg = "Decrypt";
    output_matrix(plain_text, msg);
}


void Test_ECB_Without_Two_Block(){
    cout << "Testing ECB with missing two block" << endl;
    byte plain_text[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd};
  
    byte key[16] = {0xB0, 0x25, 0x26, 0xB9,   
                    0xD5, 0xEB, 0xD9, 0x41,  
                    0x12, 0xC7, 0xED, 0x98,  
                    0x76, 0x85, 0x31, 0xA4}; 

    
    // Output the key
    string msg = "Given key is";
    output_matrix(key, msg);

    word key_array[4 * (Nr + 1)];
    Key_Expansion(key, key_array);

    msg = "Plaintext:";
    output_matrix(plain_text, msg);

    AES_Encrypt_ECB(plain_text, 16, key_array);
    msg = "Encrypt";
    output_matrix(plain_text, msg);

    AES_Decrypt_ECB(plain_text, 16, key_array);
    msg = "Decrypt";
    output_matrix(plain_text, msg);
}

void Test_CBC_Without_Two_Block(){
    cout << "Testing CBC with missing two block" << endl;
    byte plain_text[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd};
  
    byte key[16] = {0xB0, 0x25, 0x26, 0xB9,   
                    0xD5, 0xEB, 0xD9, 0x41,  
                    0x12, 0xC7, 0xED, 0x98,  
                    0x76, 0x85, 0x31, 0xA4}; 
    
    byte iv[16] = {0x10, 0x23, 0xB6, 0xB2,   
                    0xC5, 0xEC, 0x69, 0xB1,  
                    0x16, 0xA7, 0xAD, 0x92,  
                    0x56, 0xB5, 0x61, 0xA7}; 

    
    // Output the key
    string msg = "Given key is";
    output_matrix(key, msg);

    word key_array[4 * (Nr + 1)];
    Key_Expansion(key, key_array);

    msg = "Plaintext:";
    output_matrix(plain_text, msg);

    AES_Encrypt_CBC(plain_text, 16, key_array, iv);
    msg = "Encrypt";
    output_matrix(plain_text, msg);

    AES_Decrypt_CBC(plain_text, 16, key_array, iv);
    msg = "Decrypt";
    output_matrix(plain_text, msg);
}

int main(){  
    Test_Basic();
    Test_Basic_ECB();
    Test_Basic_CBC();
    Test_ECB_Without_One_Block();
    Test_CBC_Without_One_Block();
}  