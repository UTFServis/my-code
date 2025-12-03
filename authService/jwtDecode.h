#pragma once

#include "mainHeader.h"
inline tuple<string,string> decodejwt(const string& token)
{
    const string jwtSecretAccess = "MY_ACCESS_SECRET";

    try {
        auto decoded = jwt::decode(token);
        jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256{jwtSecretAccess})
        .with_issuer("auth_service")
        .verify(decoded);           
        
        string username = decoded.get_payload_claim("username").as_string();
        string role = decoded.get_payload_claim("role").as_string();
        return {username,role};
    } catch (exception& e) {
        std::cout << "JWT error: " << e.what() << std::endl;
        return { "", "" };
    }
    
}