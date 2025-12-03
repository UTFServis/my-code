#pragma once 
#include <tuple>
#include <string>
#include <cppconn/connection.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>

using namespace std;
using namespace sql;
inline tuple<string,string,string> findUser(Connection* con, const string& username) {
    try {
        PreparedStatement* pstmt = con->prepareStatement("SELECT username, password, role FROM users WHERE username = ?");
        pstmt->setString(1, username);
        ResultSet* res = pstmt->executeQuery();
        if(res->next()) {
            string u = res->getString("username");
            string hash = res->getString("password");
            string role = res->getString("role");
            delete res;
            delete pstmt;
            return make_tuple(u, hash, role);
        }
        delete res;
        delete pstmt;
        return make_tuple("", "", "");
    } catch(SQLException &e) {
        cout << "SQL Error: " << e.what() << endl;
        return make_tuple("", "", "");
    }
}