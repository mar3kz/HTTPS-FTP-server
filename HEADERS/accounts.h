#ifndef ACCOUNTS
#define ACCOUNTS

struct User_Data {
    char username[10]; // nemuzu pri deklarovani pouzivat uz rovnou definici
    char password[10];
};
// struct User_Data user_data = {.username = {0}, .password = {0}};
struct User_Data *ACCOUNTS_USER_DATA_ARRAY;

typedef enum Account_enum {
    UNSET = -1,
    ACCOUNT_EXIST = 0,
    ACCOUNT_TAKEN = 1,
    ACCOUNT_INVALID_OR_FREE = 2,
} Account_Spec;
Account_Spec Account_spec = UNSET;

#endif