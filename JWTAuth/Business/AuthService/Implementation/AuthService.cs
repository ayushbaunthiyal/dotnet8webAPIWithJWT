using JWTAuth.Models;
using JWTAuth.Business.AuthService.Interface;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuth.Business.AuthService.Implementation
{
    using BCrypt.Net;
    using Microsoft.IdentityModel.JsonWebTokens;

    public class AuthService : IAuthService
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly IConfiguration _configuration;
        public AuthService(ApplicationDbContext dbContext, IConfiguration configuration)
        {
            _dbContext = dbContext;
            _configuration = configuration;
        }

        public async Task<User> Login(string email, string password)
        {
            User? user = await _dbContext.Users.FindAsync(email);

            if (user == null || BCrypt.Verify(password, user.Password) == false)
            {
                return null; //returning null intentionally to show that login was unsuccessful
            }

            var tokenHandler = new JsonWebTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["JWT:SecretKey"]);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.GivenName, user.Name),
                    new Claim(ClaimTypes.Role, user.Role)
                }),
                IssuedAt = DateTime.UtcNow,
                Issuer = _configuration["JWT:Issuer"],
                Audience = _configuration["JWT:Audience"],
                Expires = DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            user.Token = tokenHandler.ReadJsonWebToken(token).EncodedToken;
            user.IsActive = true;

            return user;
        }

        public async Task<User> Register(User user)
        {
            user.Password = BCrypt.HashPassword(user.Password);
            _dbContext.Users.Add(user);
            try
            {
                await _dbContext.SaveChangesAsync();

            }
            catch (Exception ex)
            {

                throw;
            }
           
            return user;
        }
    }
}
