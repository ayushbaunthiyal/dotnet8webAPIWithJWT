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

namespace JWTAuth.Jwt
{
    /// <summary>
    /// MultitenantTokenValidator.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class MultitenantTokenValidator : ISecurityTokenValidator
    {
        private ILogger _logger;
        private int _maxTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
        private JwtSecurityTokenHandler _tokenHandler;


        public MultitenantTokenValidator()
        {
            _tokenHandler = new JwtSecurityTokenHandler();
        }

        /// <summary>
        /// CanValidateToken.
        /// </summary>
        public bool CanValidateToken
        {
            get
            {
                return true;
            }
        }

        /// <summary>
        /// MaximumTokenSizeInBytes.
        /// </summary>
        public int MaximumTokenSizeInBytes
        {
            get
            {
                return _maxTokenSizeInBytes;
            }

            set
            {
                _maxTokenSizeInBytes = value;
            }
        }

        /// <summary>
        /// CanReadToken.
        /// </summary>
        /// <param name="securityToken"></param>
        /// <returns></returns>
        public bool CanReadToken(string securityToken)
        {
            return _tokenHandler.CanReadToken(securityToken);
        }

        /// <summary>
        /// Validate token.
        /// </summary>
        /// <param name="securityToken"></param>
        /// <param name="validationParameters"></param>
        /// <param name="validatedToken"></param>
        /// <returns></returns>
        public ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            //Read token values using ReadToken method inside- JwtSecurityTokenHandler class.
            var token = _tokenHandler.ReadToken(securityToken) as JwtSecurityToken;

            if (token == null)
            {
                _logger.LogError("Cannot read token.", string.Format("token:{0}", securityToken));
                throw new SecurityTokenDecryptionFailedException("token");
            }

       
            var tokenAudience = token.Audiences.FirstOrDefault();

            //Call actual method which validates the token based on provided validation parameters.
            var principal = _tokenHandler.ValidateToken(securityToken, null, out validatedToken);

            return principal;
        }
    }
}

