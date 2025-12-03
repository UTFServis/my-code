#include <iostream>
#include <jwt-cpp/jwt.h>
#include <nlohmann/json.hpp>
#include "httplib.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>
#include <ctime>
#include "BCrypt.hpp"

using namespace sql;
using namespace std;
using namespace httplib;
using json = nlohmann::json;

Connection *con;
string token;
string tableName;
string tableHash;
const string jwtSecretAccess = "MY_ACCESS_SECRET";

bool verifyAccessToken(string& username,string& role,const string& token)
{
    try {
        auto decoded = jwt::decode(token);
        jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256{jwtSecretAccess})
        .with_issuer("auth_service")
        .verify(decoded);
        
        username = decoded.get_payload_claim("username").as_string();
        role = decoded.get_payload_claim("role").as_string();
        return true;
    } catch(...) {
        return false;
    }
    
}
void signup(Client& client)
{
    string username, password , passwordConfirm;
    cout << "Enter username: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;
    cout << "Enter Password confirm : ";
    cin >> passwordConfirm;
    json body = { {"username", username}, {"password", password} };
    
    httplib::Headers headers = { {"Content-Type", "application/json"} };

    auto res = client.Post("/signup", headers, body.dump(), "application/json");

    if (res) {
        cout << "Status: " << res->status << endl;
        cout << "Response: " << endl << res->body << endl;
    } else {
        cout << "POST request failed!" << endl;
    }
}

void login(Client& client)
{
    string username, password,role;
    cout << "Enter your username: ";
    cin >> username;
    cout << "Enter your password: ";
    cin >> password;
    
    json body = { {"username", username}, {"password", password} };
    httplib::Headers headers = { {"Content-Type", "application/json"} };
    auto res = client.Post("/login", headers, body.dump(), "application/json");
    
    if (res) {
        cout << "Status: " << res->status << endl;
        cout << "Response: " <<  endl << res->body << endl;
        
        json j = json::parse(res->body);
        if (j.contains("access_token")) {
            token = j.value("access_token","");
            cout << "Token saved!" << endl;
        }
        if(verifyAccessToken(username,role,token))
        {
            tableName = username + role;
        }

    } else {
        cout << "POST request failed!" << endl;
    }
}
void addTask() {
    tableHash = BCrypt::generateHash(tableName);
    string task;
    cin.ignore();
    cout << "Enter task description: ";
    getline(cin, task);

    string dateInput;
    cout << "Enter due date (YYYY-MM-DD HH:MM): ";
    getline(cin, dateInput);

    string date = dateInput + ":00";

    PreparedStatement* pstmt = con->prepareStatement(
        "INSERT INTO ? (task, date) VALUES (?, ?)"
    );
    pstmt->setString(1, tableHash + "_table" );
    pstmt->setString(2, task);
    pstmt->setString(3, date);
    pstmt->executeUpdate();
    delete pstmt;

    cout << "Task added successfully!" << endl;
}
int main()
{
    httplib::Client client("http://127.0.0.1:8080");
    Driver *driver = get_driver_instance();
    login(client);
    con = driver->connect("tcp://127.0.0.1:3306", "todoList", "123456");
    con->setSchema(tableHash + "_table");
    //signup(client);
    return 0;
}
