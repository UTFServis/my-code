#include <iostream>
#include <random>
using namespace std;
int main()
{
    char chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    random_device rd;
    string token;
    for(int i=0; i < 30 ; ++i)
    {
        token += chars[rd() % sizeof(chars) - 2];
    }
    cout << token << endl;

}