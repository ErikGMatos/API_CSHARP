using System;
using System.Configuration;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web;
using System.Web.Http;
using AutenticationJWTandREACTJS.Models;
using System.Web.Http.Cors;

namespace AutenticationJWTandREACTJS.Controllers
{
    public class LoginController : ApiController
    {
        [EnableCors(origins: "*", headers: "*", methods: "*")]
        [HttpPost]
        public IHttpActionResult Authenticate([FromBody] LoginRequest login)
        {
            var loginResponse = new LoginResponse { };
            LoginRequest loginrequest = new LoginRequest { };
            loginrequest.Username = login.Username.ToLower();
            loginrequest.Password = login.Password;

            IHttpActionResult response;
            HttpResponseMessage responseMsg = new HttpResponseMessage();
            bool isUsernamePasswordValid = false;       

            if(login != null)
            isUsernamePasswordValid=loginrequest.Password=="admin" ? true:false;
            // if credentials are valid
            if (isUsernamePasswordValid)
            {
                string token = createToken(loginrequest.Username);
                //return the token
                return Ok<string>(token);
            }
            else
            {
                // if credentials are not valid send unauthorized status code in response
                loginResponse.responseMsg.StatusCode = HttpStatusCode.Unauthorized;
                response = ResponseMessage(loginResponse.responseMsg);
                return response;
            }
        }

        private string createToken(string username)
        {
            //Set issued at date
            DateTime issuedAt = DateTime.UtcNow;
            //set the time when it expires
            DateTime expires = DateTime.UtcNow.AddHours(2);

            var tokenHandler = new JwtSecurityTokenHandler();
          
            //create a identity and add claims to the user which we want to log in
            ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, username)                
            });

            string sec = ConfigurationManager.AppSettings["secretKey"];
            var now = DateTime.UtcNow;
            var securityKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(sec));
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securityKey,Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature);
            var issuer = ConfigurationManager.AppSettings["issuer"];
            var audience = ConfigurationManager.AppSettings["audience"];

            //create the jwt
            var token =
                (JwtSecurityToken)
                    tokenHandler.CreateJwtSecurityToken(issuer:issuer,audience:audience,
                        subject: claimsIdentity, notBefore: issuedAt, expires: expires, signingCredentials: signingCredentials);
            var tokenString = tokenHandler.WriteToken(token);

            return tokenString;
        }
    }
}