#include "jwtDecode.h"
#include "verifyAccessToken.h"
#include "findUser.h"

void changeUserRole(const Request& req, Response& res)
{
    json j = json::parse(req.body);
    string newRole = j.value("new_role","");
    string path = req.path;
    string username = path.substr(7);
    if (username.empty() || path.length() <= 7)
    {
        res.status = 400;
        res.set_content("{error : username not valid}","application/json");
        return;
    }
    string authHeader  = req.get_header_value("Authorization");
    if (authHeader.empty() || authHeader.rfind("Bearer ", 0) != 0)
    {
        res.status = 403;
        res.set_content("{error : missing or invalid Authorization header }","application/json");
        return;
    }
    string token = authHeader.substr(7);

    auto [adminUsername,adminRole] = decodejwt(token);
    if (adminRole != "admin")
    {
        res.status = 403;
        res.set_content("{error : you dont have access}","application/json");
        return;
    }
    auto [user,pass,role] = findUser(con,username);
    if (user.empty())
    {
        res.status = 404;
        res.set_content("{error : user not found}","application/json");
        return;
    }
    if (!verifyAccessToken(adminUsername,adminRole,token))
    {
        res.status = 403;
        res.set_content("{error : you dont have access or token is not valid}","application/json");
        return;
    }
    try{
    PreparedStatement* update = con->prepareStatement("UPDATE users SET role = ? WHERE username = ?");
        update->setString(1,newRole);
        update->setString(2,username);
        update->executeUpdate();
        delete update;
        res.status = 200;
        res.set_content("{message : user updated was successfuly}","application/json");
    }catch(SQLException& e){
        cout << "DB error : " << e.what() << endl;
        res.status = 500;
        res.set_content("{ error : DB error}","application/json");
    }
    
    
}