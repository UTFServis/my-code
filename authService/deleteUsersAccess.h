#include "jwtDecode.h"
#include "verifyAccessToken.h"
#include "findUser.h"

void deleteUser(const Request& req, Response& res)
{
    string path = req.path;
    if (path.length() <= 7)
    {
        res.status = 400;
        res.set_content("{error : username not valid }","application/json");
        return;
    }

    string username = path.substr(7);
    string authHeader  = req.get_header_value("Authorization");
    if (authHeader.empty() || authHeader.rfind("Bearer ", 0) != 0)
    {
        res.status = 403;
        res.set_content("{error : missing or invalid Authorization header }","application/json");
        return;
    }

    string token = authHeader.substr(7);
    auto [adminUsername, adminRole] = decodejwt(token);

    if (adminRole != "admin")
    {
        res.status = 403;
        res.set_content("{error : you dont have access}","application/json");
        return;
    }

    auto [user, pass, role] = findUser(con, username);

    if (user.empty())
    {
        res.status = 404;
        res.set_content("{ error : user not found}","application/json");
        return;
    }

    if (!verifyAccessToken(adminUsername, adminRole, token))
    {
        res.status = 403;
        res.set_content("{error : you dont have access}","application/json");
        return;
    }

    try {
        PreparedStatement* del = con->prepareStatement("DELETE FROM users WHERE username = ?");
        del->setString(1, username);
        del->executeUpdate();
        delete del;

        res.status = 200;
        res.set_content("{message : user deleted successfully}","application/json");
    } catch (SQLException& e) {
        cout << "SQL Error : " << e.what() << endl;
        res.status = 500;
        res.set_content("{ error : DB error}","application/json");
    }
}
