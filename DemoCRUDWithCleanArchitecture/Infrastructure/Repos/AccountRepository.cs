using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Domain.Entity.Authentication;
using Application.DTOs.Response;
using Application.Contracts;
using System.Text;
using Application.DTOs.Request.Account;
using Application.DTOs.Response.Account;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace Infrastructure.Repos
{
    public class AccountRepository
        (RoleManager<IdentityRole> roleManager,
        UserManager<ApplicationUser> userManager, IConfiguration config,
        SignInManager<ApplicationUser> signInManager) : IAccount
    {

        private async Task<ApplicationUser> FindUserByEmailAsync(string email)
            => await userManager.FindByEmailAsync(email);

        private async Task<IdentityRole> FindRoleByNameAsync(string roleName)
            => await roleManager.FindByNameAsync(roleName);

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private async Task<string> GenerateToken(ApplicationUser user)
        {
            try
            {
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
                var userClaims = new[]
                    {
                        new Claim(ClaimTypes.Name, user.Email),
                        new Claim(ClaimTypes.Email, user.Email),
                        new Claim(ClaimTypes.Role, (await userManager.GetRolesAsync(user)).FirstOrDefault() ?? ""),
                        new Claim("Fullname", user.Name)
                    };


                var token = new JwtSecurityToken(
                    issuer: config["Jwt:Issuer"],
                    audience: config["Jwt:Audience"],
                    claims: userClaims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: credentials
                    );
                return new JwtSecurityTokenHandler().WriteToken(token);
            }
            catch { return null!; }
        }

        Task<GeneralResponse> IAccount.ChangeUserRoleAsync(ChangeUserRoleRequestDTO model)
        {
            throw new NotImplementedException();
        }

        Task<GeneralResponse> IAccount.CreateAccountAsync(CreateAccountDTO model)
        {
            throw new NotImplementedException();
        }

        Task IAccount.CreateAdmin()
        {
            throw new NotImplementedException();
        }

        Task<GeneralResponse> IAccount.CreateRoleAsync(CreateRoleDTO model)
        {
            throw new NotImplementedException();
        }

        Task<IEnumerable<GetRoleDTO>> IAccount.GetRolesAsync()
        {
            throw new NotImplementedException();
        }

        Task<IEnumerable<GetUsersWithRolesResponseDTO>> IAccount.GetUsersWithRolesAsync()
        {
            throw new NotImplementedException();
        }

        Task<LoginResponse> IAccount.LoginAccountAsync(LoginDTO model)
        {
            throw new NotImplementedException();
        }
    }
}
