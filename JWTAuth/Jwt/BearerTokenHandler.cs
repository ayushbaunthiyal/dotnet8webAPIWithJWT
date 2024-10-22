using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace JWTAuth.Jwt
{
    [ExcludeFromCodeCoverage]
    public class BearerTokenHandler : TokenHandler
    {
        private readonly JwtSecurityTokenHandler _tokenHandler = new();

        public override Task<TokenValidationResult> ValidateTokenAsync(string token, TokenValidationParameters validationParameters)
        {
            try
            {
                _tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

                if (validatedToken is not JwtSecurityToken jwtSecurityToken)
                    return Task.FromResult(new TokenValidationResult() { IsValid = false });

                return Task.FromResult(new TokenValidationResult
                {
                    IsValid = true,
                    ClaimsIdentity = new ClaimsIdentity(jwtSecurityToken.Claims, JwtBearerDefaults.AuthenticationScheme),


                    SecurityToken = jwtSecurityToken,
                });
            }

            catch (Exception e)
            {
                return Task.FromResult(new TokenValidationResult
                {
                    IsValid = false,
                    Exception = e,
                });
            }
        }
    }
}
