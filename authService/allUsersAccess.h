#include "verifyAccessToken.h"
void allUsers(const Request& req, Response& res) {
    string username, role,password;
    auto auth = req.get_header_value("Authorization");
    if(auth.empty() || auth.find("Bearer ") != 0) {
        res.status = 401;
        res.set_content("{ error : Unauthorized }", "application/json");
        return;
    }

    string token = auth.substr(7);
    if (!verifyAccessToken(username,role,token))
    {
        res.status = 401;
        res.set_content("{error : Invalid or expired token}","application/json");
        return;
    }
    
    json users = json::array();
    if (role == "admin")
    {
        try {
            PreparedStatement* pstmt = con->prepareStatement("SELECT username, role FROM users");
            ResultSet* rSet = pstmt->executeQuery();
            while(rSet->next()) {
                users.push_back({ {"username", rSet->getString("username")}, {"role", rSet->getString("role")}});
            }
            delete rSet;
            delete pstmt;
    
            res.status = 200;
            res.set_content(users.dump(), "application/json");
        } catch(sql::SQLException &e) {
            res.status = 500;
            res.set_content("{ error : Database query failed }", "application/json");
        }
    }else{
        res.status = 403;
        res.set_content("{ error : you dont have access }", "application/json");
    }
    
}