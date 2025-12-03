#include "generateAccessToken.h"
#include "generateRefreshToken.h"
#include "findUser.h"

void login(const Request& req, Response& res) {
    try {
        json j = json::parse(req.body);
        string username = j.value("username", "");
        string password = j.value("password", "");

        if(username.empty() || password.empty()) {
            res.status = 400;
            res.set_content("{error : username or password are not valid}", "application/json");
            return;
        }

        auto [u, hash, role] = findUser(con, username);
        if(u.empty()) {
            res.status = 401;
            res.set_content("{error : user not found}", "application/json");
            return;
        }

        if(BCrypt::validatePassword(password, hash)) {
            PreparedStatement* del = con->prepareStatement("DELETE FROM refresh_tokens WHERE username = ?");
            del->setString(1, username);
            del->executeUpdate();
            delete del;
            string accessToken = generateAccessToken(username,role);
            string refreshToken = generateRefreshToken(username);
            PreparedStatement* pstmt = con->prepareStatement("INSERT INTO refresh_tokens(username, refresh_token) VALUES (?, ?)");
            pstmt->setString(1, username);
            pstmt->setString(2, refreshToken);
            pstmt->executeUpdate();
            delete pstmt;
            json response = { {"success", true}, {"role", role}, {"message", "Login successful"}, {"access_token", accessToken},{"refresh_token",refreshToken}};
            res.status = 200;
            res.set_content(response.dump(), "application/json");
        } else {
            res.status = 401;
            res.set_content("{error : password is not valid}", "application/json");
        }


    } catch(SQLException &e) {
        cout << "SQL Error: " << e.what() << endl;
        res.status = 500;
        res.set_content("{ error :DB error}", "application/json");
    }
}