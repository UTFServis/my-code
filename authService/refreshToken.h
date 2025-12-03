#include "verifyRefreshToken.h"
#include "findUser.h"
void refreshToken(const Request& req, Response& res) {
    try {
        json j = json::parse(req.body);
        string refreshToken = j.value("refresh_token", "");

        if(refreshToken.empty()) {
            res.status = 400;
            res.set_content("{ error : refresh token required }", "application/json");
            return;
        }

        string username;
        string role;

        if(!verifyRefreshToken(username, refreshToken)) {
            res.status = 401;
            res.set_content("{ error : invalid or expired refresh token }","application/json");
            return;
        }

        try{
            PreparedStatement *pstmt = con->prepareStatement("SELECT refresh_token FROM refresh_tokens WHERE username = ? AND refresh_token = ?");
            pstmt->setString(1,username);
            pstmt->setString(2,refreshToken);
            ResultSet* rSet = pstmt->executeQuery();
            if (!rSet->next())
            {
                delete pstmt;
                delete rSet;
                res.status = 401;
                res.set_content("{ error : refresh token not found or revoked }", "application/json");
                return;
            }
            delete pstmt;
            delete rSet;
            
        }catch(SQLException &e){
            cout << "SQL ERROR : " << e.what() << endl;
            res.status = 500;
            res.set_content("{ error : DB error}", "application/json");
            return;
        }
        {
            auto [user,pass,rolee] = findUser(con,username);
            role = rolee.empty() ? "user" : rolee;
        }
        
        string newAccessToken = generateAccessToken(username, role);
        json response = { {"access_token", newAccessToken}, {"message", "new access token generated"}, {"success", true}};

        res.status = 200;
        res.set_content(response.dump(), "application/json");

    } catch(...) {
        res.status = 500;
        res.set_content("{error : server error}", "application/json");
    }
}