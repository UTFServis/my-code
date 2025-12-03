#include "mainHeader.h"

sql::Connection* con = nullptr;
const string jwtSecretAccess = "MY_ACCESS_SECRET";
const string jwtSecretRefresh = "MY_REFRESH_SECRET";

#include "signUp.h"
#include "login.h"
#include "refreshToken.h"
#include "deleteUsersAccess.h"
#include "changeUsersRoleAccess.h"
#include "allUsersAccess.h"



int main() {
    try {
        Driver* driver = get_driver_instance();
        con = driver->connect("tcp://127.0.0.1:3306", "testuser", "123456");
        con->setSchema("testdb");

        Server server;
        server.Post("/signup", signUp);
        server.Post("/login", login);
        server.Post("/refresh", refreshToken);
        server.Delete(R"(/users/.*)", deleteUser);
        server.Put(R"(/users/.*)", changeUserRole);
        server.Get("/users", allUsers);

        cout << "Server starting ..." << endl;
        server.listen("0.0.0.0", 8080);

    } catch(SQLException &e) {
        cout << "Database connection error: " << e.what() << endl;
    }
}