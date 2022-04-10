// ===========================================
//
// Password Strength Analyzer
// by :
//    - Daniel Jayasutra
//    - Firly Adianov
//    - M. Faizal Syahroni
//    - Septian Pramana R.
//
// ===========================================


#include <iostream>
#include <cstdlib>
#include <conio.h>


using namespace std;

const int LBOUND_NUMBER = 48;
const int UBOUND_NUMBER = 57;

const int LBOUND_UCASE  = 65;
const int UBOUND_UCASE  = 90;

const int LBOUND_LCASE  = 97;
const int UBOUND_LCASE  = 122;

const int LBOUND_SYMB1  = 32;
const int UBOUND_SYMB1  = 47;

const int LBOUND_SYMB2  = 58;
const int UBOUND_SYMB2  = 64;

const int LBOUND_SYMB3  = 91;
const int UBOUND_SYMB3  = 96;

const int LBOUND_SYMB4  = 123;
const int UBOUND_SYMB4  = 126;

const int LBOUND_ASCII_PRINTABLE = LBOUND_SYMB1;
const int UBOUND_ASCII_PRINTABLE = UBOUND_SYMB4;

const int ENTER = 13;
const int BACKSPACE = 8;

const int MAX_LENGTH  = 50;

const int EXCELLENT_LENGTH  = 12;
const int SAFE_LENGTH       = 8;
const int BAD_LENGTH        = 5;

struct PwString {
    char* container;
    int length;

    PwString(char*& chr, int len) {
        container = chr;
        length = len;
    }

    ~PwString() {

        // Due to sensitive data, set to null before destroy the memory to prevent memory dump.
        for(int i = 0; i < length; i++){
            container[i] = '\0';
        }

        delete container;       // Delete memory allocation
        container = nullptr;    // Prevent dangling pointer
    }
};

enum InputType {
    OTHER       = 0,
    NUMERIC     = 1,
    SYMBOL      = 2,
    CHAR_UCASE  = 3,
    CHAR_LCASE  = 4,
};

InputType validateChar(char& chr) {
    int asciiCode = (int)chr;

     // Check number
    if(asciiCode >= LBOUND_NUMBER && asciiCode <= UBOUND_NUMBER){
        return InputType::NUMERIC;
    }

    // Check U-Case
    if(asciiCode >= LBOUND_UCASE && asciiCode <= UBOUND_UCASE){
       return InputType::CHAR_UCASE;
    }

    // Check L-Case
    if(asciiCode >= LBOUND_LCASE && asciiCode <= UBOUND_LCASE){
        return InputType::CHAR_LCASE;
    }

    // Check symbol / special character
    if(asciiCode >= LBOUND_SYMB1 && asciiCode <= UBOUND_SYMB1){
        return InputType::SYMBOL;
    }

    // Check symbol / special character
    if(asciiCode >= LBOUND_SYMB2 && asciiCode <= UBOUND_SYMB2){
        return InputType::SYMBOL;
    }

    // Check symbol / special character
    if(asciiCode >= LBOUND_SYMB3 && asciiCode <= UBOUND_SYMB3){
        return InputType::SYMBOL;
    }

    // Check symbol / special character
    if(asciiCode >= LBOUND_SYMB4 && asciiCode <= UBOUND_SYMB4){
        return InputType::SYMBOL;
    }

    return InputType::OTHER;
}

/**
*
* Analyze password strength
*/
void analyze(PwString& password) {

    char*& input = password.container;
    int& length  = password.length;

    int strength = 0; // Default score is 0

    if(length >= EXCELLENT_LENGTH){
        strength = 2;  // if length is more than 12 character, add 2 to score
    }
    else if (length >= SAFE_LENGTH){
        strength = 1;  // if length is more than 8 character, add 1 to score
    }
    else if (length < BAD_LENGTH){
        strength = -1; // if length is less than 5, deduct 1 to score
    }

    bool hasUCase  = false;
    bool hasLCase  = false;
    bool hasNumber = false;
    bool hasSymbol = false;

    // Analyze char per char
    for(int i = 0; i < length; i++){

        InputType type = validateChar(input[i]);

        switch(type) {
        case NUMERIC:
            hasNumber = true;
            break;

        case SYMBOL:
            hasSymbol = true;
            break;

        case CHAR_UCASE:
            hasUCase = true;
            break;

        case CHAR_LCASE:
            hasLCase = true;
            break;

        default:
            // NoOp
            break;
        }
    }

    cout << "Result : " << endl;

    if (strength < 1) {
        cout << "- [X] ";
    }
    else{
        cout << "- [V] ";
    }
    cout << "Password have at least 8 characters" << endl;

    if(hasUCase && hasLCase){
        strength += 1;
        cout << "- [V] ";
    } else {
        cout << "- [X] ";
    }
    cout << "Password contains upper and lower case" << endl;

    if(hasNumber){
        strength += 1;
        cout << "- [V] ";
    }
    else {
        cout << "- [X] ";
    }
    cout << "Password contain at least one number" << endl;

    if(hasSymbol){
        strength += 1;
        cout << "- [V] ";
    }
    else {
        cout << "- [X] ";
    }
    cout << "Password contain at least a symbol or special character" << endl;

    cout << "Overall score: ";

    switch(strength) {
    case 5 :
        cout << " [Excellent]" << endl;
        break;

    case 4 :
        cout << " [Strong]" << endl;
        break;

    case 3 :
        cout << " [Medium]" << endl;
        break;

    case 2 :
        cout << " [Weak]" << endl;
        break;

    default :
        cout << " [Worst]" << endl;
        break;
    }
}

/**
*
*   read password masked
*/
PwString readPassword() {
    char* x = new char[MAX_LENGTH];

    // Initialization, set pointer value to null
    for(int i = 0; i < MAX_LENGTH; i++){
        x[i] = '\0';
    }

    // Mask input password

    // Any special character made by combination of null any any other character.
    bool skipFlag = false;
    for(int i = 0; i < MAX_LENGTH;){
        char input = getch();

        if(skipFlag){
            skipFlag = false;
            continue;
        }

        // if input is enter, stop loop
        if(input == '\r') {
            cout << endl;
            return PwString(x, i);
        }

        // if input is backspace
        if(input == '\b'){
            if(i > 0){
                x[--i] = '\0'; //make the previous byte null if backspace is pressed
                cout << "\b" << " " << "\b"; // Remove mask by whitespace
            }

            continue;
        }

        // Validate ASCII printable char
        int asciiCode = (int) input;
        if(asciiCode == -32 || asciiCode == 0){
            skipFlag = true;
            continue;
        }

        if(asciiCode < LBOUND_ASCII_PRINTABLE) {
            continue;
        }

        if(asciiCode > UBOUND_ASCII_PRINTABLE) {
            continue;
        }

        x[i] = input;
        i += 1;
        cout << "*";
    }

    cout << endl;
    return PwString(x, MAX_LENGTH);;
}

int main()
{
    cout << "Password Strength Analyzer" << endl;

    while(true){
        cout << endl << endl;
        cout<<"Enter password: ";
        PwString str = readPassword();
        analyze(str);
    }

    return 0;
}
